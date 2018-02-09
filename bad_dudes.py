#!/usr/bin/env python3
from datetime import time, date, datetime
import netmiko
import re
import sqlite3
from bad_dudes_config import USERNAME, PASSWORD, IP_ADDRESS, PREFIX_LIST

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun":6,
          "Jul":7, "Aug":8, "Sep":9, "Oct":10, "Nov":11, "Dec":12}
SSH_FAILED_LOGIN_REGEX = "(?P<month>\w+)\s+(?P<day>\d+)\s(?P<time>([0-9]{1,2}:){2}[0-9]{1,2})\s+(?P<year>[0-9]{4}).*(?:user ')(?P<user>.*)'\s.*(?:host ')((?P<ip_address>.*)')"

SSH_ACCOUNTS_INSERT = "INSERT INTO ssh_accounts(ssh_account, first_seen) VALUES (?,?)"
SSH_ACCOUNTS_SELECT_BY_PK = "SELECT * FROM ssh_accounts WHERE pk='{0}'"
SSH_ACCOUNTS_SELECT_BY_SSH_ACCOUNT = "SELECT * FROM ssh_accounts WHERE ssh_account='{0}'"
SSH_IP_ADDRESS_INSERT = "INSERT INTO ip_addresses(ip_address, first_seen) VALUES (?,?)"
SSH_IP_ADDRESS_SELECT_BY_NOT_BLOCKED = "SELECT * FROM ip_addresses WHERE is_blocked='0'"
SSH_IP_ADDRESS_SELECT_BY_PK = "SELECT * FROM ip_addresses WHERE pk='{0}'"
SSH_IP_ADDRESS_SELECT_BY_IP_ADDRESS = "SELECT * FROM ip_addresses WHERE ip_address='{0}'"
SSH_FAILED_LOGIN_INSERT = "INSERT INTO failed_login_log(ip_address, ssh_account, timestamp) VALUES (?,?,?)"
SSH_FAILED_LOGIN_SELECT_BY_IP_ADDRESS = "SELECT * FROM failed_login_log WHERE ip_address='{0}'"
SSH_FAILED_LOGIN_SELECT_BY_ALL = "SELECT * FROM failed_login_log WHERE ip_address='{0}' AND ssh_account='{1}' AND timestamp='{2}'"
SSH_FAILED_LOGIN_SELECT_COMP01 = "SELECT COUNT(pk) AS count, ip_address, ssh_account FROM failed_login_log WHERE ip_address='{0}' GROUP BY ssh_account ORDER BY count"


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


def ssh_get_pk(con, select_query, select_column, insert_query, match_dict, should_i_create):
    _cursor = con.cursor()
    _cursor.execute(select_query.format(match_dict[select_column]))
    row = _cursor.fetchone()

    if row is None:
        if should_i_create:
            _cursor.execute(insert_query, (match_dict[select_column],
                                           datetime.combine(match_dict["date"], match_dict["time"])))
            con.commit()
            _cursor.execute(select_query.format(match_dict[select_column]))
            row = _cursor.fetchone()
        else:
            return None

    return row[0]


def add_to_database(con, match_dict):
    _cursor = con.cursor()

    ip_pk = ssh_get_pk(con, SSH_IP_ADDRESS_SELECT_BY_IP_ADDRESS, "ip_address", SSH_IP_ADDRESS_INSERT, match_dict, False)
    ssh_pk = ssh_get_pk(con, SSH_ACCOUNTS_SELECT_BY_SSH_ACCOUNT, "username", SSH_ACCOUNTS_INSERT, match_dict, False)

    row = None
    if ip_pk is not None and ssh_pk is not None:
        _cursor.execute(SSH_FAILED_LOGIN_SELECT_BY_ALL.format(ip_pk, ssh_pk,
                                                              datetime.combine(match_dict["date"], match_dict["time"])))
        row = _cursor.fetchone()

    if row is None:
        ip_pk = ssh_get_pk(con, SSH_IP_ADDRESS_SELECT_BY_IP_ADDRESS, "ip_address",
                           SSH_IP_ADDRESS_INSERT, match_dict, True)
        ssh_pk = ssh_get_pk(con, SSH_ACCOUNTS_SELECT_BY_SSH_ACCOUNT, "username",
                            SSH_ACCOUNTS_INSERT, match_dict, True)

        _cursor.execute(SSH_FAILED_LOGIN_INSERT, (ip_pk,
                                                  ssh_pk,
                                                  datetime.combine(match_dict["date"], match_dict["time"])))
        con.commit()
    else:
        print("row already present")


def return_first_row_colx(con, select_str, colx):
    _cursor = con.cursor()
    _cursor.execute(select_str)

    row = _cursor.fetchone()
    if row is not None:
        return row[colx]

    return None


def shall_we_block(con, block_list):
    _cursor = con.cursor()
    _cursor.execute(SSH_IP_ADDRESS_SELECT_BY_NOT_BLOCKED)

    rows = _cursor.fetchall()
    for row in rows:
        _cursor.execute(SSH_FAILED_LOGIN_SELECT_COMP01.format(row[0]))
        remote_host_rows = _cursor.fetchall()

        row_count = 0
        for remote_host_row in remote_host_rows:
            row_count = row_count + 1
            if row_count >= 3 or remote_host_row[0] > 3:
                # block ip because 3 failures logged with different accounts.
                # or block ip because 3 failures logged with the same account
                block_list.append(return_first_row_colx(con, SSH_IP_ADDRESS_SELECT_BY_PK.format(remote_host_row[1]), 1))
                break

    return block_list


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
                        "ip_address TEXT, first_seen TIMESTAMP, is_blocked INTEGER DEFAULT 0)")

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

    # print_database(con)

    block_list = shall_we_block(con, [])


    print(block_list)

    # print(device_connection.send_command("configure"))
    device_connection.config_mode()
    print(device_connection.find_prompt())
    j_prompt = device_connection.find_prompt()
    print(device_connection.send_command(command_string="edit policy-options prefix-list {0}".format(PREFIX_LIST),
                                         expect_string=j_prompt))
    for ip in block_list:
        print("blocking ip: {0}".format(ip))
        print(device_connection.send_command(command_string="set {0}".format(ip), expect_string=j_prompt))

    print(device_connection.send_command(command_string="commit and-quit", expect_string=j_prompt))




if __name__ == "__main__":
    main()
