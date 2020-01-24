from unittest import TestCase
from datetime import time, date

import bad_dudes

class Test(TestCase):
    def test_get_device_prefix_list(self):
        test_ar = bad_dudes.get_device_prefix_list("juniper", ["5.2.200.196/32;", "5.89.10.81/32;"])
        self.assertEqual(test_ar, ["5.2.200.196/32", "5.89.10.81/32"])

    def test_get_full_match_cisco(self):
        self.assertEqual(None, bad_dudes.get_full_match("foo", "cisco"))

    def test_get_full_match_juniper(self):
        input_str = "Jan 24 21:16:48 2020  3C_R01 sshd: SSHD_LOGIN_FAILED: Login failed for user 'emf' from host " +\
                    "'142.44.160.173'"
        self.assertDictEqual({"username": "emf", "ip_address": "142.44.160.173", "date": date(2020, 1, 24),
                              "time": time(21, 16, 48)},
                             bad_dudes.get_full_match(input_str, "juniper"))
