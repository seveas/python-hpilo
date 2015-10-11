#!/usr/bin/python

from utils import *
import random

class UserTests(IloTestCase):
    test_user_login = 'ilotestuser'

    @classmethod
    def setUpClass(cls):
        for ilo in cls.ilos.values():
            try:
                ilo.delete_user(cls.test_user_login)
            except hpilo.IloUserNotFound:
                pass
    tearDownClass = setUpClass

    def test_user_creation(self, ilo):
        alphabet = 'abcdefghijklmnopqrstuvwxyz'
        alphabet += alphabet.upper()
        password = ''.join([random.choice(alphabet) for i in range(random.randint(20,30))])
        ilo.add_user(self.test_user_login, 'python-hpilo test user', password,
                     admin_priv=False, remote_cons_priv=False, reset_server_priv=False,
                     virtual_media_priv=False, config_ilo_priv=False)
        user = ilo.get_user(self.test_user_login)
        self.assertFalse(user['admin_priv'])
        self.assertFalse(user['remote_cons_priv'])

    def test_user_manipulation(self, ilo):
        ilo.mod_user(self.test_user_login, remote_cons_priv=True)
        user = ilo.get_user(self.test_user_login)
        self.assertFalse(user['admin_priv'])
        self.assertTrue(user['remote_cons_priv'])

    def test_user_ssh_keys(self, ilo):
        ssh_key = ''.join(['ssh-dss AAAAB3NzaC1kc3MAAACBAIpNY5fvLSS3MCjGNKjuWH',
                           'rFGR5J6vLqdqIrXttTz7o6GWtmyxcC0Mlp2c/h1bMfvUiKDvDp',
                           '+5T7SGo/2R+aXLaPwYtm6eBPEBU2CgVTnpeVELDeaJ/tr0kTL/',
                           'PKMHZDFgT9c7/hOiWr4amlGvuxs60MP/xs4jWaxLxabhjiRoCL',
                           'AAAAFQChDEFySo74rpPNNWfvJHgiylTbRQAAAIEAgo8UQqXP7g',
                           'MTAUdHTqlzoTnj3loc4ZTnf3W6jr25cs5XaXNnRtadfw0G4VWa',
                           'S/uDyNhsq/o2nFrhWTwAvojWSe4C5MDdGGerktL1ZY/QfoxB0d',
                           '7aK/dlHd1iOVpGahCqyzmhEDmEnq6TWd6cBVHNVcryLEJVVtaf',
                           '8QmJlwS+XkIAAACAJGnuO6ZJ1S2AMOY1uOpov/srTyuu6Pxtcn',
                           'HsHA5wNoNQFcYElnDndJUfMAPi0vzODntHoiOGdrX3RcjxSAB5',
                           'lAgNZwFnwGWoAa8UIQlX+GwDYAIk+8G36tmHRgtl7xJlFqs9W6',
                           'BhrJEmfL4ubWCPXl/yMDrrLnMQuV3Mg0DNVSg= Test key'])
        ilo.import_ssh_key(self.test_user_login, ssh_key)
        ilo.delete_ssh_key(self.test_user_login)

    def test_z_user_deletion(self, ilo):
        ilo.delete_user(self.test_user_login)
        self.assertRaises(hpilo.IloUserNotFound, ilo.get_user, self.test_user_login)

if __name__ == '__main__':
    unittest.main()
