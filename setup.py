#!/usr/bin/python

from setuptools import setup

setup(name = "python-hpilo",
      version = "4.4.1",
      author = "Dennis Kaarsemaker",
      author_email = "dennis@kaarsemaker.net",
      url = "http://github.com/seveas/python-hpilo",
      description = "iLO automation from python or shell",
      py_modules = ["hpilo", "hpilo_fw"],
      scripts = ["hpilo_cli"],
      classifiers = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: System :: Hardware',
        'Topic :: System :: Systems Administration',
        'Topic :: System :: Networking',
      ]
)
