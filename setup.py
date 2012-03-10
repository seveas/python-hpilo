#!/usr/bin/python

from distutils.core import setup

setup(name = "python-hpilo",
      version = "1.0",
      author = "Dennis Kaarsemaker",
      author_email = "dennis@kaarsemaker.net",
      url = "http://github.com/seveas/python-hpilo",
      description = "Accessing HP iLO interfaces from python",
      py_modules = ["hpilo"],
      scripts = ["hpilo_cli", "hpilo_ca"],
      classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python :: 2',
        'Topic :: System :: Hardware',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Networking',
      ]
)
