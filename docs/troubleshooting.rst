Common issues
=============
The iLO interfaces aren't the most helpful when they detect something
erroneous. These are some common issues and their solutions. If you have a
problem that is not listed here, or solved with these instructions, please file
an issue at https://github.com/seveas/python-hpilo. When reporting bugs, please
do send the problematic XML responses. These XML responses can be saved as
follows::

  hpilo_cli example-server.int.kaarsemaker.net --save-response=for_bugreport.txt get_fw_version

Of course you should replace the hostname  with the actual iLO hostname or ip,
and get_fw_version with the actual call you want to make. If you use the python
API instead of the CLI tool, set the :data:`save_response` attribute on the ilo
object::

  ilo = hpilo.Ilo(hostname, login, password)
  ilo.save_response = "for_bugreport.txt"
  ilo.get_fw_version()

These debug responses may contain sensitive information, which you should edit
out. Please use a hexeditor to do so, or at least make sure your editor does
not try to normalize newlines. It is important that the number of characters in
the file stays the same, so don't add or remove data, just overwrite sensitive
values with XXXX.

As github issues do not support attachments, feel fee to mail this debug
information to `the author`_ directly.

.. _`the author`: mailto:dennis@kaarsemaker.net

Update your firmware
--------------------
This might sound like a lame cop-out, but quite a few versions of especially
iLO 3 firmware contain serious bugs that cause the XML interface to misbehave.
Upgrading the firmware of an iLO is simple and does not impact the host at all,
so it's always a good idea to start with a firmware update::

  hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware version=latest

If this fails to extract the firmware, try upgrading python-hpilo as newer
firmware versions are shipped in a different, incompatible format.

Syntax error: Line #0
---------------------
Occasionally you might see this error at the end of a traceback::

  hpilo.IloError: Error communicating with iLO: Syntax error: Line #0: syntax error near "" in the line: ""

This generally means that you are trying to call a method that is not supported
for your device or the firmware version you use. Get this information with::

  hpilo_cli example-server.int.kaarsemaker.net get_fw_version

And consult the HP sample XML files to find out whether this call is supported
for your device and firmware version. If it is, please file a bug report.

Note that for some calls (most notable mod_global_settings), support for the
call may be there, but not all arguments are supported.

SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:661)
------------------------------------------------------------------------------
Your operating system vendor wisely doesn't support older SSL protocols
anymore, and your iLO firmware is too old. Try using an older version of your
os, possibly in a vm, chroot or container to upgrade the firmware of your iLO

ElementTree.ParseError
-----------------------
Occasionally you might see either of these errors at the end of a traceback::

  cElementTree.ParseError: not well-formed (invalid token): line 301, column 23
  xml.etree.ElementTree.ParseError: not well-formed (invalid token): line 301, column 23

This means that the iLO interface is spewing invalid XML back at you.
python-hpilo has some workarounds in place for common cases, and most other
cases have been fixed in newer firmware versions. Please update your firmware
version and try again. If the problem persists, please file a bug report.

Unexpected errors after a login failure
---------------------------------------
If you use the wrong credentials to access the XML interface, some iLO's get
into some weird state. Call :func:`get_fw_version` a few times to clear this
state and recover.

Failure to update iLO3 firmware
-------------------------------
The early firmware versions of iLO3 had quite a few issues. To update from
anything older than 1.28 to 1.50 or newer, you need to update in two steps:
first update to 1.28 and then update to a later version::

  hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware version=1.28
  hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware version=latest

Failure to update iLO5 firmware
-------------------------------
The early firmware versions of iLO3 had quite a few issues. To update from
anything older than 1.40 to 1.50 or newer, you need to update in two steps:
first update to 1.40 and then update to a later version::

  hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware version=1.40
  hpilo_cli example-server.int.kaarsemaker.net update_rib_firmware version=latest

`hpilo.IloError: Error reading configuration`
---------------------------------------------
This error might occur in delayed mode when one of the calls causes a reset of
the iLO, such as changing network settings or resetting to factory defaults. All
delayed calls called by the same `call_delayed` after this reset may then cause
this error as the iLO is resetting. For example, when calling `hpilo_cli
localhost factory_defaults + activate_license key=12345`, the
`activate_license` call may fail with this error. If you hit this issue and you
use calls that can cause a reset, make sure you either use them outside a
delayed call or at the end of the delayed call.
