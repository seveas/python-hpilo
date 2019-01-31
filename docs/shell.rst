Access from the shell
=====================

The commandline interface, :program:`hpilo_cli`,  allows you to make calls from
your shell or scripts written in another language than python. It supports all
methods that the library has.

``hpilo_cli`` usage
-------------------

.. highlight:: console

.. code-block:: console

    hpilo_cli [options] hostname method [args...] [ + method [args...]...]
    hpilo_cli download_rib_firmware ilotype version [version...]

Contacts the iLO, calls one or more methods and displays the output as if you
were using a python console.

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
    -y, --yaml            Output a yaml document instead of a python dict
    -P PROTOCOL, --protocol=PROTOCOL
                          Use the specified protocol instead of autodetecting
    -d, --debug           Output debug information, repeat to see all XML data
    -o PORT, --port=PORT  SSL port to connect to
    --ssl-verify          Verify SSL certificates against the trusted CA's
    --ssl-ca-file=SSL_CA_FILE
                          CA bundle to validate iLO certificate against, instead
                          of the system CA's
    --ssl-ignore-hostname
                          Don't check if the hostname matches the certificate
                          when verifying SSL certificates
    -h, --help            show this help message or help for a method
    -H, --help-methods    show all supported methods

:program:`hpilo_cli` will read a config file (by default :file:`~/.ilo.conf`)
to find login information and any other variable you wish to set. This config
file is a simple ini file that should look like this

.. code-block:: ini

  [ilo]
  login = Administrator
  password = AdminPassword

Using such a file is recommended over using the login/password commandline
arguments.

Many methods that can be called require arguments. These arguments must be
specified as :data:`key=value` pairs on the command-line. These parameters can
also point to arbitrary configuration variables using the
:attr:`key='$section.option'` syntax.

Finally, you can also call multiple methods at once by separating them with a
:data:`+`

Examples
--------

As you can see, the :program:`hpilo_cli` program is quite versatile. Some
examples will make it clearer how to use this application properly.

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

Methods like :func:`mod_network_data` method require dicts for some arguments
(e.g. :data:`static_route_`), you can use the following syntax::

  $ hpilo_cli example-server.int.kaarsemaker.net mod_network_settings static_route_1.dest=1.2.3.4 static_route_1.gateway=10.10.10.254

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

``-P local`` is optional when specifying localhost as hostname, so this works too::

  $ hpilo_cli localhost mod_user user_login=Administrator password=NewPassword

If hponcfg is not in the default install location and not in your :data:`$PATH`
or :data:`%PATH%`, you can set an alternative path in the configuration file.

.. code-block:: ini

  [ilo]
  hponcfg = /usr/local/bin/hponcfg

Available methods
-----------------
All methods available to the python API are also available to the command line.
These methods are documented separately in further pages here and in the `ilo
scripting guide`_ published by Hewlett Packard Enterprise.

.. _`hp`: http://www.hpe.com/info/ilo
.. _`ilo scripting guide`: http://www.hpe.com/support/ilo4_cli_gde_en
