iLO automation from python or shell
===================================

HP servers come with a powerful out of band management interface called
Integrated Lights out, or iLO. It has an extensive web interface and
commercially available tools for centrally managing iLO devices and their
servers.

But if you want to build your own tooling, integrate iLO management to your
existing procedures or simply want to manage iLOs using a command-line
interface, you're stuck manually creating XML files and using a perl hack HP
ships called `locfg.pl`.

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

The available functions you can call are all documented in the pages linked
below, but for detailed descriptions of all functions and especially their
arguments, please refer to the `ilo scripting guide`_ as well.

This package also ships examples of more complete applications in the `examples`
directory. This include an automated CA for managing SSL certificates, tooling
to centralize iLO information in elastic search and an automated firmware
updater. All of which are used in production by the author or other
contributors.

Compatibility
=============
This module is written with compatibility as main priority. Currently supported
are:

* All RILOE II/iLO versions up to and including iLO 5
* Python 2.6-2.7 and python 3.5 and newer
* Any operating system Python runs on

iLOs can be managed both locally using `hponcfg` or remotely using the iLO's
built-in webserver. In the latter case, the requirements above concern the
machine you run this code on, not the managed server.

Getting started
===============
.. toctree::
   :maxdepth: 1

   install
   python
   shell

Available functionality
=======================
.. toctree::
   :maxdepth: 1

   info
   networksettings
   license
   authentication
   security
   health
   power
   boot
   media
   input
   snmp
   firmware
   xmldata
   log
   federation
   ahs
   profile

Example applications
====================
There are several example applications in the `examples/` directory. Note that
while `hpilo.py` and `hpilo_cli` are compatible with python versions as old as
2.6, some examples may require newer versions of python and have additional
dependencies.

.. toctree::
   :maxdepth: 1

   ca
   elasticsearch
   autofirmware
   puppet

Development information
=======================
.. toctree::
   :maxdepth: 1

   troubleshooting
   contributing

Author and license
==================
This software is (c) 2011-2021 Dennis Kaarsemaker <dennis@kaarsemaker.net>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

HP, Integrated Lights out and iLO are trademarks of HP, with whom the author of
this software is not affiliated in any way.

.. _`ilo scripting guide`: http://www.hp.com/support/ilo4_cli_gde_en
