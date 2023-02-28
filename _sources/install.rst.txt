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

The easiest way is to install with pip:

.. code-block:: console

   $ pip3 install python-hpilo

You can also download the package from `PyPI`_ and install it manually like any
other application by unpacking it and running ``python setup.py install``.

.. _`PyPI`: http://pypi.python.org/packages/source/p/python-hpilo/, extract it and run

Users of supported Fedora and RHEL/CentOS releases can also use my COPR repository:

.. code-block:: console

   $ sudo dnf install dnf-plugins-core
   $ sudo dnf copr enable seveas/python-hpilo
   $ sudo dnf install python-hpilo
