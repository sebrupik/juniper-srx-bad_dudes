#!/usr/bin/env python3
import json
import sqlite3
from ipwhois import IPWhois


IP_ADDRESS_SELECT_BY_NULL_ASN_CIDR = "SELECT * FROM ip_addresses WHERE asn_cidr is NULL"

SQL_TOP_USERNAME = "SELECT COUNT(fll.pk) AS count, (SELECT ssh_account FROM ssh_accounts WHERE pk=fll.ssh_account) FROM failed_login_log fll GROUP BY ssh_account ORDER BY count DESC LIMIT 10"



def whois_this(ip):
    obj = IPWhois(ip)
    results = obj.lookup_rdap(depth=1)

    return {"asn": results["asn"], "asn_cidr": results["asn_cidr"],
            "asn_country_code": results["asn_country_code"], "asn_description": results["asn_description"]}


def main():
    con = sqlite3.connect('bad_dudes.db')
    _cursor = con.cursor()
    _cursor.execute(SQL_TOP_USERNAME)
    rows = _cursor.fetchall()

    print("Top 10 usernames")
    for row in rows:
        print(row)


    # _cursor.execute


if __name__ == "__main__":
    main()