iLO automation from python or shell
===================================

HP servers come with a powerful out of band management interface called
Integrated Lights out, or iLO. It has an extensive web interface and
commercially available tools for centrally managing iLO devices and their
servers.

But if you want to built your own tooling, integrate iLO management to your
existing procedures or simply want to manage iLOs using a command-line
interface, you're stuck manually creating XML files and using a perl hack HP
ships called locfg.pl.

Enter python-hpilo!

Using the same XML interface as HP's own management tools, here is a python
library and command-line tool that make it a lot easier to do all the above. No
manual XML writing, just call functions from either python or your
shell(script).

Usage
-----
Full usage documentation can be found on http://seveas.github.io/python-hpilo/
or in the docs/ directory in the python-hpilo tarball. Here are some examples
to wet your appetite:

Getting the chassis IP of a blade server, from python:

    >>> ilo = hpilo.Ilo('example-server.int.kaarsemaker.net')
    >>> chassis = ilo.get_oa_info()
    >>> print chassis['ipaddress']
    10.42.128.101

Entering a license key and creating a user, from the shell:

    $ hpilo_cli example-server.int.kaarsemaker.net activate_license key=$mykey
    $ hpilo_cli example-server.int.kaarsemaker.net add_user user_login=dennis \
                password=hunter2 admin_priv=true

Compatibility
-------------
This module is written with compatibility as main priority. Currently supported
are:

* All RILOE II/iLO versions up to and including iLO 4
* Python 2.6 or 2.7, and python 3.5 and newer
* Any operating system Python runs on

iLOs can be managed both locally using `hponcfg` or remotely using the iLO's
built-in webserver. In the latter case, the requirements above concern the
machine you run this code on, not the managed server.

Author and license
------------------
This software is (c) 2011-2021 Dennis Kaarsemaker <dennis@kaarsemaker.net>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

HP, Integrated Lights out and iLO are trademarks of HP, with whom the author of
this software is not affiliated in any way other than using some of their
hardware.
