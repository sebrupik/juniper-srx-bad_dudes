#!/usr/bin/env python3
import sqlite3
from bad_dudes import get_asn_cidr_pk

IP_ADDRESS_SELECT_BY_NULL_ASN_CIDR = "SELECT * FROM ip_addresses WHERE asn_cidr is NULL"
IP_ADDRESS_UPDATE_ASN_CIDR = "UPDATE ip_addresses SET asn_cidr='{0}' WHERE pk='{1}'"

SQL_TOP_USERNAME = "SELECT COUNT(fll.pk) AS count, (SELECT ssh_account FROM ssh_accounts WHERE pk=fll.ssh_account) " + \
                   "FROM failed_login_log fll GROUP BY ssh_account ORDER BY count DESC LIMIT {0}"
SQL_TOP_ASN = "SELECT COUNT(asn_cidr.pk) AS count, (SELECT asn_desc FROM asns WHERE pk=asn_cidr.asn) " + \
              "FROM asn_cidr GROUP BY asn ORDER BY count DESC LIMIT {0}"
SQL_TOP_ASN_BY_SOURCE_IPS = "SELECT COUNT(pk) AS count, " + \
                            "(SELECT asn FROM asn_cidr WHERE pk=ip_addresses.asn_cidr) AS as_number " + \
                            "FROM ip_addresses GROUP BY as_number ORDER BY count"


def print_some_output(con, sql_statement, limit, header):
    _cursor = con.cursor()
    _cursor.execute(sql_statement.format(limit))
    rows = _cursor.fetchall()

    print(header.format(limit))
    for row in rows:
        print(row)


def main():
    con = sqlite3.connect('bad_dudes.db')

    print_some_output(con, SQL_TOP_USERNAME, 10, "Top {0} usernames")

    _cursor = con.cursor()
    _cursor.execute(IP_ADDRESS_SELECT_BY_NULL_ASN_CIDR)
    rows = _cursor.fetchall()
    for row in rows:
        _cursor.execute(IP_ADDRESS_UPDATE_ASN_CIDR.format(get_asn_cidr_pk(con, row[1]), row[0]))

    con.commit()

    print_some_output(con, SQL_TOP_ASN, 15, "Top {0} CIDR grouped by ASN")


if __name__ == "__main__":
    main()
