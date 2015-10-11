import unittest
import ConfigParser
import json
import os
import sys
import time
import re

testroot = os.path.dirname(__file__)
sys.path.insert(0, os.path.dirname(testroot))

import hpilo
import warnings
warnings.filterwarnings("ignore", category=hpilo.IloWarning)

class FirmwareCache(object):
    def __init__(self):
        self.cachefile = os.path.join(testroot, '.firmware_version_cache')
        self.cache = {}
        if os.path.exists(self.cachefile):
            with open(self.cachefile) as fd:
                self.cache = json.load(fd)

    def __getitem__(self, ilo):
        if ilo.hostname not in self.cache:
            self.cache[ilo.hostname] = ilo.get_fw_version()
            with open(self.cachefile, 'w') as fd:
                json.dump(self.cache, fd)
        return self.cache[ilo.hostname]
firmware_cache = FirmwareCache()

class IloTestCaseMeta(type):
    def __new__(cls, name, bases, attrs):
        attrs['ilos'] = {}
        config = ConfigParser.ConfigParser()
        config.read(os.path.expanduser(os.path.join('~', '.ilo.conf')))
        login = config.get('ilo', 'login')
        password = config.get('ilo', 'password')
        methods = []
        for attr in list(attrs.keys()):
            if attr.startswith('test_') and callable(attrs[attr]):
                attrs['_' + attr] = attrs.pop(attr)
                methods.append(attr[5:])

        for section in config.sections():
            if not section.startswith('test '):
                continue
            key = section.split()[1]
            hostname = config.get(section, 'ilo')
            ilo = hpilo.Ilo(hostname, login, password)
            ilo.firmware_version = firmware_cache[ilo]
            if not ilo.protocol:
                ilo.protocol = hpilo.ILO_RAW if ilo.firmware_version['management_processor'].lower() in ('ilo', 'ilo2') else hpilo.ILO_HTTP

            ilo.save_response = os.path.join(testroot, 'hpilo_test_debug_output')
            attrs['ilos'][key] = ilo
            for method in methods:
                fname = re.sub('[^a-zA-Z0-9_]', '_', 'test_%s_%s' % (key, method))
                attrs[fname] = eval("lambda self: self._test_%s(self.ilos['%s'])" % (method, key))
        return super(IloTestCaseMeta, cls).__new__(cls, name, bases, attrs)

class IloTestCase(unittest.TestCase):
    __metaclass__ = IloTestCaseMeta
    maxDiff = None

    def require_ilo(self, ilo, *ilos):
        for ilov in ilos:
            version = None
            if ':' in ilov:
                ilov, version = ilov.split(':')
            if ilo.firmware_version['management_processor'].lower() == ilov:
                if not version or ilo.firmware_version['firmware_version'] >= version:
                    return True

        raise unittest.SkipTest("This test requires %s, not %s:%s" % ('|'.join(ilos), 
            ilo.firmware_version['management_processor'].lower(), ilo.firmware_version['firmware_version']))

    def reset_delay(self, ilo):
        time.sleep(30)
        while True:
            try:
                ilo.get_fw_version()
                return
            except hpilo.IloCommunicationError:
                time.sleep(10)
