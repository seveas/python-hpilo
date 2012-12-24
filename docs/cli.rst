hpilo_cli command-line tool
===========================

The commandline interface allows you to make calls from your shell or scripts
written in another language than python. It supports all methods that the
library has and is used as follows::

  Usage: hpilo_cli [options] hostname method [args...]

  Options:
    -l LOGIN, --login=LOGIN
                          Username to access the iLO
    -p PASSWORD, --password=PASSWORD
                          Password to access the iLO
    -i, --interactive     Prompt for username and/or password if they are not
                          specified.
    -c FILE, --config=FILE
                          File containing authentication and config details
    -t TIMEOUT, --timeout=TIMEOUT
                          Timeout for iLO connections
    -j, --json            Output a json document instead of a python dict
    -P PROTOCOL, --protocol=PROTOCOL
                          Use the specified protocol instead of autodetecting
    -d, --debug           Output debug information, repeat to see all XML data
    -o PORT, --port=PORT  SSL port to connect to
    --untested            Allow untested methods
    -h, --help            show this help message or help for a method
    -H, --help-methods    show all supported methods

The configuration file (by default :file:`~/.ilo.conf` is a simple ini file
that should look like this::

  [ilo]
  login = Administrator
  password = AdminPassword

Using such a file is recommended over using the login/password commandline
arguments. A full example config file is shipped with the hpilo distribution.

To pass arguments to method calls, pass :attr:`key=value` pairs on the
command-line. These can reference arbitrary configuration variables using
:attr:`key='$section.option'`

You can also call multiple methds at once by separating them with a :data:`+`

Some examples will make it clearer, so here are a few:

Getting the status of the UID light::

  $ hpilo_cli example-server.int.kaarsemaker.net get_uid_status
  >>> print(my_ilo.get_uid_status())
  OFF

Getting virtual cdrom status in JSON format::

  $ hpilo_cli example-server.int.kaarsemaker.net get_vm_status --json
  {"write_protect": "NO", "vm_applet": "DISCONNECTED", "image_url": "", "boot_option": "NO_BOOT", "device": "CDROM", "image_inserted": "NO"}

Setting the name of the server::

  $ hpilo_cli example-server.int.kaarsemaker.net set_server_name name=example-server

Displaying help for the :func:`get_host_data` method::

  $ hpilo_cli --help get_host_data
  Ilo.get_host_data [decoded_only=True]:
  Get SMBIOS records that describe the host. By default only the ones
  where human readable information is available are returned. To get
  all records pass decoded_only=False

Calling multiple methods::

  $ hpilo_cli example-server.int.kaarsemaker.net get_uid_status + uid_control uid=No + get_uid_status
  >>> print(my_ilo.get_uid_status())
  ON
  >>> my_ilo.uid_control(uid="No")
  >>> print(my_ilo.get_uid_status())
  OFF

Setting a licence key defined in the config file::

  $ cat ~/.ilo.conf
  [ilo]
  login = Administrator
  password = AdminPass

  [license]
  ilo3_advanced = FAKEL-ICENS-EFORH-PILO3-XXXXX

  $ hpilo_cli example-server.int.kaarsemaker.net activate_license key='$license.ilo3_advanced'

Using hponcfg to talk to the local iLO device to reset the password without knowing it::

  $ hpilo_cli -P local localhost mod_user user_login=Administrator password=NewPassword

-P local is optional when specifying localhost as hostname, so this works too::

  $ hpilo_cli localhost mod_user user_login=Administrator password=NewPassword

If hponcfg is not at :file:`/sbin/hponcfg` or
:file:`C:\\Program Files\\HP Lights-Out Configuration Utility\\cpqlocfg.exe`, you
can set an alternative path in the config, see the example config file.
