#!/usr/bin/python

from utils import *

class UidTests(IloTestCase):
    def test_uid(self, ilo):
        old = ilo.get_uid_status()
        new = {'ON': 'No', 'OFF': 'Yes'}[old]
        new2 = {'ON': 'OFF', 'OFF': 'ON'}[old]
        try:
            ilo.uid_control(uid=new)
            self.assertEqual(new2, ilo.get_uid_status())
        finally:
            ilo.uid_control(uid=old)

if __name__ == '__main__':
    unittest.main()
