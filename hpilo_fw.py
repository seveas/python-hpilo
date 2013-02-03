# Downloader / extracter for latest iLO2 / iLO3 / iLO4 firmware
#
# (c) 2011-2013 Dennis Kaarsemaker <dennis@kaarsemaker.net>
# see COPYING for license details

import tarfile
import os
import sys
PY3 = sys.version_info[0] >= 3

if PY3:
    import urllib.request as urllib2
    import configparser as ConfigParser
    from io import BytesIO, StringIO
    b = lambda x: bytes(x, 'ascii')
    GZIP_CONSTANT = '\x1f\x8b'.encode('latin-1')
else:
    import urllib2
    import ConfigParser
    from cStringIO import StringIO as StringIO
    BytesIO = StringIO
    b = lambda x: x
    GZIP_CONSTANT = '\x1f\x8b'

_config = None
def config():
    global _config
    if not _config:
        conf = _download('https://raw.github.com/seveas/python-hpilo/master/firmware.conf')
        if PY3:
            conf = conf.decode('ascii')
        parser = ConfigParser.ConfigParser()
        parser.readfp(StringIO(conf))
        _config = {}
        for section in parser.sections():
            _config[section] = {}
            for option in parser.options(section):
                _config[section][option] = parser.get(section, option)
    return _config

def _download(url):
    req = urllib2.urlopen(url)
    size = int(req.headers['Content-Length'])
    if size < 4096:
        return req.read()
    downloaded = 0
    data = b('')
    while downloaded < size:
        new = req.read(4096)
        data += new
        downloaded += len(new)
        sys.stdout.write('\r\033[K%d/%d (%d%%)' % (downloaded, size, downloaded*100.0/size))
        sys.stdout.flush()
    print("")
    return data

def download(ilo, path=None):
    if not path:
        path = os.getcwd()
    conf = config()
    if os.path.exists(os.path.join(path, conf[ilo]['file'])):
        return
    print("Downloading %s firmware version %s" % (ilo, conf[ilo]['version']))
    scexe = _download(conf[ilo]['url'])

    # An scexe is a shell script with an embedded compressed tarball. Find the tarball.
    skip_start = scexe.index(b('_SKIP=')) + 6
    skip_end = scexe.index(b('\n'), skip_start)
    skip = int(scexe[skip_start:skip_end]) - 1
    tarball = scexe.split(b('\n'), skip)[-1]

    # Now uncompress it
    if tarball[:2] != GZIP_CONSTANT:
        raise ValueError("Downloaded scexe file seems corrupt")

    tf = tarfile.open(name="bogus_name_for_old_python_versions", fileobj=BytesIO(tarball), mode='r:gz')
    tf.extract(conf[ilo]['file'], path)

if __name__ == '__main__':
    path = os.getcwd()
    if len(sys.argv) > 1:
        path =  sys.argv[1]
    conf = config()
    [download(x, path) for x in conf]
