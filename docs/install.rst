Installing python-hpilo
=======================

This module is easy to install and has very few extra dependencies. For the
convenience of users of major linux distributions, I also ship packages that
you can install with the standard package manager.

Dependencies
------------

Always needed:

* `Python`_ 2.6, 2.7, 3.5 or newer

Sometimes needed:

* If you want to use the ``LOCAL`` protocol, talking to the iLO from the server
  it is installed in via a kernel driver, you need to install this driver and
  the ``hponcfg`` tool from `hp`_
* Some example applications require additional software. More details about
  these requirements can be found in the documentation of those examples.

.. _`python`: http://www.python.org
.. _`hp`: http://www.hp.com/go/ilo


Installing the latest release
-----------------------------

When using Ubuntu, Debian, Fedora, CentOS or RHEL, it is advisable to use the
deb or rpm packages I create for every release, so you get automatic updates
whenever a new release is issued.

Users of Ubuntu releases that Canonical still supports can use my launchpad
PPA:

.. code-block:: console

   $ sudo add-apt-repository ppa:dennis/python
   $ sudo apt-get update
   $ sudo apt-get install python-hpilo

Users of supported Fedora and RHEL/CentOS releases can ue my COPR repository:

.. code-block:: console

   $ sudo dnf install dnf-plugins-core
   $ sudo dnf copr enable seveas/python-hpilo
   $ sudo dnf install python-hpilo

Or for older releases, using yum:

.. code-block:: console

   $ sudo yum install yum-plugin-copr
   $ sudo yum copr enable seveas/python-hpilo
   $ sudo yum install python-hpilo

And for even older releases, where yum-plugin-copr isn't available, you can
download a .repo file from `COPR`_ to copy to ``/etc/yum.repos.d``.

.. _`COPR`: https://copr.fedorainfracloud.org/coprs/seveas/python-hpilo/

If you can not, or do not want to use these packages (for example, if you use
windows or osx, or if you want to install into a virtualenv) you can download
the package from `PyPI`_ and install it manually like any other application by
unpacking it and running ``python setup.py install``. Or use ``pip`` to install
it: ``pip install python-hpilo``

.. _`PyPI`: http://pypi.python.org/packages/source/p/python-hpilo/, extract it and run
