#!/usr/bin/python

from utils import *

class DelayedTests(IloTestCase):
    def test_delayed_calls(self, ilo):
        uid = {'ON': 'Yes', 'OFF': 'No'}[ilo.get_uid_status()]
        non_delayed = [
            ilo.get_all_users(),
            ilo.get_global_settings(),
        ]
        try:
            ilo.delayed = True
            ilo.get_all_users()
            ilo.uid_control(uid=uid)
            ilo.get_global_settings()
            delayed = ilo.call_delayed()
        finally:
            ilo.delayed = False
        self.assertEquals(non_delayed, delayed)

if __name__ == '__main__':
    unittest.main()
