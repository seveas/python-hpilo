#!/usr/bin/python

from utils import *

class NetworkTests(IloTestCase):
    def test_mod_network_settings(self, ilo):
        old = ilo.get_network_settings()
        try:
            ilo.mod_network_settings(ter_dns_server='10.1.1.1')
            self.reset_delay(ilo)
            new = ilo.get_network_settings()
            self.assertEquals(new['ter_dns_server'], '10.1.1.1')
        finally:
            ilo.mod_network_settings(ter_dns_server='' if old['ter_dns_server'] == '0.0.0.0' else old['ter_dns_server'])
            self.reset_delay(ilo)

    def test_ipv6_routes(self, ilo):
        self.require_ilo(ilo, 'ilo3:1.50', 'ilo4:1.20')

if __name__ == '__main__':
    unittest.main()
