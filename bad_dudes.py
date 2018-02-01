#!/usr/bin/env python3
from datetime import time, date, datetime
import netmiko
import re
import sqlite3
from bad_dudes_config import USERNAME, PASSWORD, IP_ADDRESS

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun":6,
          "Jul":7, "Aug":8, "Sep":9, "Oct":10, "Nov":11, "Dec":12}
SSH_FAILED_LOGIN_REGEX = "(?P<month>\w+)\s+(?P<day>\d+)\s(?P<time>([0-9]{1,2}:){2}[0-9]{1,2})\s+(?P<year>[0-9]{4}).*(?:user ')(?P<user>.*)'\s.*(?:host ')((?P<ip_address>.*)')"

SSH_ACCOUNTS_INSERT = "INSERT INTO ssh_accounts(ssh_account, first_seen) VALUES (?,?)"
SSH_IP_ADDRESS_INSERT = "INSERT INTO ip_addresses(ip_address, first_seen) VALUES (?,?)"
SSH_FAILED_LOGIN_INSERT = "INSERT INTO failed_login_log(ip_address, ssh_account, timestamp) VALUES (?,?,?)"



def get_hostname(input_str):
    match = re.search('[@](.*)[>]', input_str)
    if match:
        return match.group(1)

    return None


def get_timestamp(match, datetime_obj):
    if match:
        datetime_obj["date"] = date(int(match.group("year")), MONTHS[match.group("month")], int(match.group("day")))

        arr = match.group("time").split(":")
        datetime_obj["time"] = time(int(arr[0]), int(arr[1]), int(arr[2]))

        return datetime_obj

    return None


def get_full_match(input_str):
    match = re.search(SSH_FAILED_LOGIN_REGEX, input_str)
    if match:
        match_dict = get_timestamp(match, {})
        if match_dict is not None:
            match_dict["username"] = match.group("user")
            match_dict["ip_address"] = match.group("ip_address")

            return match_dict

    return None

def ssh_get_username(con, match_dict):
    _cursor = con.cursor()
    _cursor.execute("SELECT * from ssh_accounts WHERE ssh_account = '{0}'".format(match_dict["username"]))
    row_user = _cursor.fetchone()

    if row_user is None:
        _cursor.execute(SSH_ACCOUNTS_INSERT, (match_dict["username"],
                                              datetime.combine(match_dict["date"], match_dict["time"])))
        con.commit()
        _cursor.execute("SELECT pk FROM ssh_accounts WHERE ssh_account='{0}'".format(match_dict["username"]))
        row_user = _cursor.fetchone()

    return row_user[0]


def ssh_get_ip_address(con, match_dict):
    _cursor = con.cursor()
    _cursor.execute("SELECT * from ip_addresses WHERE ip_address = '{0}'".format(match_dict["ip_address"]))
    row_ip = _cursor.fetchone()

    if row_ip is None:
        print("we don't have {0}, lets add it".format(match_dict["ip_address"]))

        _cursor.execute(SSH_IP_ADDRESS_INSERT, (match_dict["ip_address"],
                                                datetime.combine(match_dict["date"], match_dict["time"])))
        con.commit()
        _cursor.execute("SELECT pk FROM ip_addresses WHERE ip_address='{0}'".format(match_dict["ip_address"]))
        row_ip = _cursor.fetchone()

    return row_ip[0]


def add_to_database(con, match_dict):
    _cursor = con.cursor()
    _cursor.execute(SSH_FAILED_LOGIN_INSERT, (ssh_get_ip_address(con, match_dict),
                                              ssh_get_username(con, match_dict),
                                              datetime.combine(match_dict["date"], match_dict["time"])))
    con.commit()


def print_database(con):
    _cursor = con.cursor()
    _cursor.execute("SELECT * FROM failed_login_log")

    rows = _cursor.fetchall()
    for row in rows:
        print(row)


def main():
    con = sqlite3.connect('bad_dudes.db')
    _cursor = con.cursor()
    _cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_addresses'")
    row = _cursor.fetchone()

    if row is None:
        # build the tables
        con = sqlite3.connect('bad_dudes.db')
        _cursor = con.cursor()
        _cursor.execute("CREATE TABLE ip_addresses (pk INTEGER PRIMARY KEY," +
                        "ip_address TEXT, first_seen TIMESTAMP)")

        _cursor.execute("CREATE TABLE ssh_accounts (pk INTEGER PRIMARY KEY," +
                        "ssh_account TEXT, first_seen TIMESTAMP)")

        _cursor.execute("CREATE TABLE failed_login_log (pk INTEGER PRIMARY KEY," +
                        "ip_address INTEGER, ssh_account INTEGER," +
                        "timestamp TIMESTAMP," +
                        "FOREIGN KEY (ip_address) REFERENCES ip_addresses(pk)," +
                        "FOREIGN KEY (ssh_account) REFERENCES ssh_accounts(pk))")

    device_connection = netmiko.ConnectHandler(device_type="juniper",
                                               ip=IP_ADDRESS,
                                               username=USERNAME,
                                               password=PASSWORD)

    ssh_output = device_connection.send_command("show log messages | match SSHD_LOGIN_FAILED | no-more")

    count = 0
    for line in ssh_output.splitlines():
        print("{0}, {1}".format(count, line))
        count = count + 1

        match_dict = get_full_match(line)
        print(match_dict)
        if match_dict is not None:
            add_to_database(con, match_dict)


    print_database(con)


if __name__ == "__main__":
    main()
