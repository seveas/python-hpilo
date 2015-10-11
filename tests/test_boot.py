#!/usr/bin/python

from utils import *
import random

class BootTests(IloTestCase):
    def test_persistent_boot(self, ilo):
        old = ilo.get_persistent_boot()
        new = old[:]
        random.shuffle(new)
        try:
            ilo.set_persistent_boot(new)
            self.assertEqual(new, ilo.get_persistent_boot())
        finally:
            ilo.set_persistent_boot(old)

    def test_one_time_boot(self, ilo):
        old = ilo.get_one_time_boot()
        all = ilo.get_persistent_boot()
        if old in all:
            all.remove(old)
        new = random.choice(all)
        try:
            ilo.set_one_time_boot(new)
            self.assertEqual(new, ilo.get_one_time_boot())
        finally:
            ilo.set_one_time_boot(old)

if __name__ == '__main__':
    unittest.main()
