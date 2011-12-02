Accessing HP iLO interfaces from python
=======================================

This module will make it easy for you to access the Integrated Lights Out
management interface of your HP hardware. It supports iLO, iLO 2 and iLO 3 and
It uses the XML interface to access and change the iLO.

A command line interface to this module, :file:`hpilo_cli` makes accessing iLO
interfaces almost trivial and easy to integrate with non-python scripts.

HP, Integrated Lights out and iLO are trademarks of HP, with whom the author of
this software is not affiliated in any way other than using some of their
hardware.

iLO obects
~~~~~~~~~~
.. class:: Ilo(hostname, username, password, timeout=60)

The :class:`Ilo` class encapsulates all functionality. It autodetects which iLO
version is in use and will send the correct messages for that version. Its
methods are divided into several categories below: getting information,
changing settings and upgrading firmware.

Getting information
-------------------
These functions get various bits of information from your iLO interface. As
they're easiest to explain by wht they return, I'm limiting the explanations to
example output.

.. function:: get_all_user_info()

  >>> pprint(my_ilo.get_all_user_info())
  {'Administrator': {'admin_priv': True,
                     'config_ilo_priv': True,
                     'remote_cons_priv': True,
                     'reset_server_priv': True,
                     'user_login': 'Administrator',
                     'user_name': 'Administrator',
                     'virtual_media_priv': True}}

.. function:: get_all_users()

  >>> pprint(my_ilo.get_all_users())
  ['Administrator']

.. function:: get_global_settings()

  >>> pprint(my_ilo.get_global_settings())
  {'authentication_failure_logging': 'Enabled-every 3rd failure',
   'enforce_aes': False,
   'f8_login_required': False,
   'f8_prompt_enabled': True,
   'http_port': 80,
   'https_port': 443,
   'ilo_funct_enabled': True,
   'min_password': 8,
   'rbsu_post_ip': True,
   'remote_console_port': 17990,
   'serial_cli_speed': 9600,
   'serial_cli_status': 'Enabled-Authentication Required',
   'session_timeout': 30,
   'ssh_port': 22,
   'ssh_status': True,
   'virtual_media_port': 17988}

.. function:: get_twofactor_settings()

  >>> pprint(my_ilo.get_twofactor_settings())
  {'auth_twofactor_enable': False,
   'cert_owner_subject': None,
   'cert_revocation_check': False}

The commandline interface
~~~~~~~~~~~~~~~~~~~~~~~~~

The commandline interface allows you to make calls from your shell or scripts
written in another language than python. It supports all methods that the
library has and is used as follows::

  $ hpilo_cli --help

  Usage: hpilo_cli [options] hostname method [args...]
      
  Supported methods:
  - get_all_user_info
  - get_all_users
  - get_global_settings
  - get_twofactor_settings
  
  Options:
    -l LOGIN, --login=LOGIN
                          Username to access the iLO
    -p PASSWORD, --password=PASSWORD
                          Password to access the iLO
    -a FILE, --auth=FILE  File containing authentication details
    -t TIMEOUT, --timeout=TIMEOUT
                          Timeout for iLO connections
    -j, --json            Output a json document instead of a python dict
    -d, --debug           Output debug information, repeat to see all XML data
    -h, --help            show this help message or help for a method

The authentication file is a simple ini file that should look like this::

  [ilo]
  login = Administrator
  password = AdminPassword

Using such a file is recommended over using the login/password commandline
arguments.

Contents:
=========

.. toctree::
   :maxdepth: 2
