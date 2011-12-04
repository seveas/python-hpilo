hpilo_cli command-line tool
===========================

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
