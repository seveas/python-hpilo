Common issues
=============
The iLO interfaces aren't the most helpful when they detect something
erroneous. These are some common issues and their solutions. If you have a
problem that is not listed here, or solved with these instructions, please file
an issue at https://github.com/seveas/python-hpilo

Syntax error: Line #0
---------------------
Occasionally you might see this error at the end of a traceback::

  hpilo.IloError: Error communicating with iLO: Syntax error: Line #0: syntax error near "" in the line: ""

This generaly means that you are trying to call a method that is not supported
for your device or the firmware version you use. Get this information with::

  hpilo_cli your.host.name.here get_fw_version

And consult the HP sample XML files to find out whether this call is supported
for your device and firmware version. If it is, please file a bug at
https://github.com/seveas/python-hpilo.

Note that for some calls (most notable mod_global_settings), support for the
call may be there, but not all arguments are supported.

ElementTree.ParseError
-----------------------
Occasionally you might see either of these errors at the end of a traceback::

  cElementTree.ParseError: not well-formed (invalid token): line 301, column 23
  xml.etree.ElementTree.ParseError: not well-formed (invalid token): line 301, column 23

This means that the iLO interface is spewing invalid XML back at you.
python-hpilo has some workarounds in place for common cases, and most other
cases have been fixed in newer firmware versions. Please update your firmware version::

  hpilo_cli your.host.name.here update_rib_firmware filename=latest

and try again. If the problem persists, run the hpilo_cli command in debugging
mode (-dd) and submit a bug with the resulting XML fragment.
