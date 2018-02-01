import re
from datetime import time, date


months = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun":6,
          "Jul":7, "Aug":8, "Sep":9, "Oct":10, "Nov":11, "Dec":12}

def gethostname(input):
    match = re.search('[@](.*)[>]', input)
    if match:
        return match.group(1)


def gettimestamp(input, hostname):
    match = re.search("(.*){0}".format(hostname), input)
    if match:
        return match.group(1)


def get_timestamp(input_str, hostname):
    match = re.search("(.*){0}".format(hostname), input_str)
    datetime_obj = {}

    if match:
        arr = match.group(1).split()
        datetime_obj["date"] = date(int(arr[3]), months[arr[0]], int(arr[1]))

        arr = arr[2].split(":")
        datetime_obj["time"] = time(int(arr[0]), int(arr[1]), int(arr[2]))

        return datetime_obj

    return None


def get_username(input):
    match = re.search("(?:user ')(.*)'\s", input)
    if match:
        return match.group(1)


def get_ip_address(input):
    match = re.search("(?:host ')(.*)'", input)
    if match:
        return match.group(1)

def get_full_match(input_str):
    match = re.search("(?P<month>\w+)\s(?P<day>\d+)\s(?P<time>([0-9]{1,2}:){2}[0-9]{1,2}).*(?:user ')(?P<user>.*)'\s.*(?:host ')((?P<ip_address>.*)')", input_str)
    if match:
        return match

    return None


input01 = "admin@CS7-SRX01>"
input02 = "Jan 30 14:57:37  2018 CS7-SRX01 sshd: SSHD_LOGIN_FAILED: Login failed for user 'FORCE' from host '193.201.224.214'"


print(gethostname(input01))
print(get_timestamp(input02, gethostname(input01)))
print(get_username(input02))
print(get_ip_address(input02))

match_va = get_full_match(input02)
print(match_va.group("month"))
