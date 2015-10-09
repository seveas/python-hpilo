#!/usr/bin/python

from utils import *

class RequestsTestMeta(type):
    def __new__(cls, name, parents, attrs):
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'xml')
        for machine in os.listdir(root):
            mdir = os.path.join(root, machine)
            if not os.path.isdir(mdir):
                continue

            files = os.listdir(mdir)
            for argsfile in files:
                if not argsfile.endswith('.args'):
                    continue
                method = argsfile[:argsfile.find('-')]
                reqfile = argsfile.replace('.args', '.request')
                reqtmpfile = argsfile.replace('.args', '.request.tmp')
                argspath = os.path.join(mdir, argsfile)
                reqpath = os.path.join(mdir, reqfile)
                reqtmppath = os.path.join(mdir, reqtmpfile)
                fname = 'test_%s_%s' % (machine, argsfile[:-5])
                fname = re.sub('[^a-zA-Z_0-9]', '_', fname).lower()
                attrs[fname] = eval("lambda self: self._test_request('%s', '%s', '%s', '%s', '%s')" % 
                                    (machine, method, argspath, reqpath, reqtmppath))
        return super(RequestsTestMeta, cls).__new__(cls, name, parents, attrs)

class RequestsTest(unittest.TestCase):
    __metaclass__ = RequestsTestMeta
    maxDiff = None

    def _test_request(self, machine, method, argsfile, reqfile, reqtmpfile):
        ilo = hpilo.Ilo('nonexistent-machine','Administrator','TestPassword')
        if 'ilo3' in machine.lower() or 'ilo4' in machine.lower():
            ilo.protocol = hpilo.ILO_HTTP
        else:
            ilo.protocol = hpilo.ILO_RAW
        if os.path.exists(reqtmpfile):
            os.unlink(reqtmpfile)
        ilo.save_request = reqtmpfile
        with open(argsfile) as fd:
            args, kwargs = eval(fd.read()), {}
        if isinstance(args, dict):
            args, kwargs = [], args

        if not os.path.exists(reqfile):
            self.assertRaises(ValueError, getattr(ilo, method), *args, **kwargs)
            return

        getattr(ilo, method)(*args, **kwargs)
        with open(reqfile) as fd:
            old = fd.read()
        with open(reqtmpfile) as fd:
            new = fd.read()
        self.assertMultiLineEqual(old, new)
        os.unlink(reqtmpfile)

if __name__ == '__main__':
    unittest.main()
