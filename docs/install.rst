Installing
==========

python-hpilo requires python 2.4 or newer, python 3 is supported as well.
:file:`hpilo_ca` requires that you have OpenSSL installed. When using python
2.4, installing cElementTree is required as well. 2.5 and newer have this
library as part of the standard library.

If you want to use the hpilo.LOCAL protocol, talking directly to the iLO via a
kernel driver, you must install this driver and the relevant tools from hp.

Installing the latest release
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Installing the latest released version is as simple as::

  pip install python-hpilo

This downloads it from PyPI and installs it for you. Alternatively, you can
download the tarball manually from
http://pypi.python.org/packages/source/p/python-hpilo/, extract it and run::

  python setup.py install

Installing the development version
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you want to tinker around with the source, or simply live on the bleeding
edge of development, you can install the latest source from github::

  git clone https://github.com/seveas/python-hpilo.git
  cd python-hpilo
  ./hpilo_cli -h
