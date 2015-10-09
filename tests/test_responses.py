#!/usr/bin/python

from utils import *
import pprint

class ResponsesTestMeta(type):
    def __new__(cls, name, parents, attrs):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xml')
        for machine in os.listdir(root):
            mdir = os.path.join(root, machine)
            if not os.path.isdir(mdir):
                continue

            files = os.listdir(mdir)
            for rawfile in files:
                if not rawfile.endswith('.raw'):
                    continue
                method = rawfile.replace('.raw', '')
                parsedfile = rawfile.replace('.raw', '.parsed')
                rawpath = os.path.join(mdir, rawfile)
                parsedpath = os.path.join(mdir, parsedfile)
                fname = 'test_%s_%s' % (machine, method)
                fname = re.sub('[^a-zA-Z_0-9]', '_', fname).lower()
                attrs[fname] = eval("lambda self: self._test_response('%s', '%s', '%s', '%s')" % 
                                    (machine, method, rawpath, parsedpath))
        return super(ResponsesTestMeta, cls).__new__(cls, name, parents, attrs)

class ResponsesTest(unittest.TestCase):
    __metaclass__ = ResponsesTestMeta
    maxDiff = None
    method_args = {
        'get_user': ['Administrator'],
        'get_federation_group': ['slartibartfast'],
    }
    def _test_response(self, machine, method, rawfile, parsedfile):
        ilo = hpilo.Ilo('nonexistent-machine','Administrator','TestPassword')
        if 'ilo3' in machine.lower() or 'ilo4' in machine.lower():
            ilo.protocol = hpilo.ILO_HTTP
        else:
            ilo.protocol = hpilo.ILO_RAW
        ilo.read_response = rawfile

        args = self.method_args.get(method, [])
        if not os.path.exists(parsedfile):
            self.assertRaises(hpilo.IloError, getattr(ilo, method), *args)
            return
        response = getattr(ilo, method)(*args)
        new = pprint.pformat(response) + '\n'
        with open(parsedfile) as fd:
            old = fd.read()
        self.assertMultiLineEqual(old, new)

if __name__ == '__main__':
    unittest.main()
