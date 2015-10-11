#!/usr/bin/python

from utils import *
import time

class LogTests(IloTestCase):
    def test_ilo_event_log(self, ilo):
        ilo.clear_ilo_event_log()
        time.sleep(2)
        log = ilo.get_ilo_event_log()
        self.assertTrue(type(log) != dict)
        self.assertTrue(len(log) <= 3)

if __name__ == '__main__':
    unittest.main()
