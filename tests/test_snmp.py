#!/usr/bin/python

from utils import *

class SnmpTests(IloTestCase):
    def test_mod_snmp_im_settings(self, ilo):
        old = ilo.get_snmp_im_settings()
        try:
            ilo.mod_snmp_im_settings(snmp_address_3='10.42.42.42', rib_traps=True)
            new = ilo.get_snmp_im_settings()
            self.assertEqual(new['snmp_address_3'], '10.42.42.42')
            self.assertEqual(new['rib_traps'], True)
        finally:
            ilo.mod_snmp_im_settings(snmp_address_3=old['snmp_address_3'], rib_traps=old['rib_traps'])

    def test_snmp_user_profiles(self, ilo):
        self.require_ilo(ilo, 'ilo4')

if __name__ == '__main__':
    unittest.main()
