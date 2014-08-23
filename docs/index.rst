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

Quick usage examples
====================
Full usage documentation can be found following the links below, but here are
some examples to wet your appetite:

Getting the chassis IP of a blade server, from python::

    >>> ilo = hpilo.Ilo('example-server.int.kaarsemaker.net')
    >>> chassis = ilo.get_oa_info()
    >>> print chassis['ipaddress']
    10.42.128.101

Entering a license key and creating a user, from the shell:

.. code-block:: console

    $ hpilo_cli example-server.int.kaarsemaker.net activate_license key=$mykey
    $ hpilo_cli example-server.int.kaarsemaker.net add_user user_login=dennis \
                password=hunter2 admin_priv=true

This package also ships examples of more complete applications in the examples
directory. This include an automated CA for managing SSL certificates, tooling
to centralize iLO informatin in elastic search and an automated firmware
updater. All of which are used in production by the author or other
contributors.

Compatibility
=============
This module is written with compatibility as main priority. Currently supported
are:

* All RILOE II/iLO versions up to and including iLO 4
* Python 2.4-2.7 and python 3.2 and newer
* Any operating system Python runs on

iLOs can be managed both locally using `hponcfg` or remotely using the iLO's
built-in webserver. In the latter case, the requirements above concern the
machine you run this code on, not the managed server.

Available functionality
=======================

.. toctree::
   :maxdepth: 1

   install
   python
   shell
   info
   network
   authentication
   security
   license
   health
   power
   boot
   media
   snmp
   firmware
   xmldata
   log
   ahs
   ers
   profile

Example applications
====================
.. toctree::
   :maxdepth: 1

   ca
   elasticsearch
   autofirmware

Development information
=======================
.. toctree::
   :maxdepth: 1

   troubleshooting
   contributing

Author and license
==================
This software is (c) 2011-2014 Dennis Kaarsemaker <dennis@kaarsemaker.net>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

HP, Integrated Lights out and iLO are trademarks of HP, with whom the author of
this software is not affiliated in any way.
