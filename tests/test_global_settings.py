#!/usr/bin/python

from utils import *

class GlobalSettingsTests(IloTestCase):
    def test_mod_global_settings(self, ilo):
        old = ilo.get_global_settings()
        try:
            ilo.mod_global_settings(
                f8_login_required=True,
                min_password=3
            )
            new = ilo.get_global_settings()
            self.assertEqual(new['f8_login_required'], True)
            self.assertEqual(new['min_password'], 3)
        finally:
            ilo.mod_global_settings(
                f8_login_required=old['f8_login_required'],
                min_password=old['min_password']
            )

if __name__ == '__main__':
    unittest.main()
