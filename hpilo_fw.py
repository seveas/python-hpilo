# Downloader / extracter for latest iLO2 / iLO3 / iLO4 firmware
#
# (c) 2011-2015 Dennis Kaarsemaker <dennis@kaarsemaker.net>
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
def config(mirror=None):
    global _config
    if not _config:
        if mirror:
            conf = _download(mirror + 'firmware.conf')
        else:
            conf = _download('https://raw.githubusercontent.com/seveas/python-hpilo/master/firmware.conf')
        if PY3:
            conf = conf.decode('ascii')
        parser = ConfigParser.ConfigParser()
        parser.readfp(StringIO(conf))
        _config = {}
        for section in parser.sections():
            _config[section] = {}
            for option in parser.options(section):
                _config[section][option] = parser.get(section, option)
    if mirror:
        for section in _config:
            _config[section]['url'] = mirror + _config[section]['file']
    return _config

def download(ilo, path=None, progress = lambda txt: None):
    if not path:
        path = os.getcwd()
    conf = config()
    if not os.path.exists(os.path.join(path, conf[ilo]['file'])):
        msg  = "Downloading %s firmware version %s" % (ilo.split()[0], conf[ilo]['version'])
        progress(msg)
        data = _download(conf[ilo]['url'], lambda txt: progress('%s %s' % (msg, txt)))
        if conf[ilo]['url'].endswith('.bin'):
            fd = open(os.path.join(path, conf[ilo]['file']), 'w')
            fd.write(data)
            fd.close()
        else:
            _parse(data, path, conf[ilo]['file'])
        return True
    return False

def parse(fwfile, ilo):
    fd = open(fwfile)
    data = fd.read()
    fd.close()
    if '_SKIP=' in data:
        # scexe file
        fwfile = _parse(data, os.getcwd())
    return fwfile

def _download(url, progress=lambda txt: None):
    req = urllib2.urlopen(url)
    size = int(req.headers['Content-Length'])
    if size < 16384:
        return req.read()
    downloaded = 0
    data = b('')
    while downloaded < size:
        new = req.read(16384)
        data += new
        downloaded += len(new)
        progress('%d/%d bytes (%d%%)' % (downloaded, size, downloaded*100.0/size))
        sys.stdout.flush()
    return data

def _parse(scexe, path, filename=None):
    # An scexe is a shell script with an embedded compressed tarball. Find the tarball.
    skip_start = scexe.index(b('_SKIP=')) + 6
    skip_end = scexe.index(b('\n'), skip_start)
    skip = int(scexe[skip_start:skip_end]) - 1
    tarball = scexe.split(b('\n'), skip)[-1]

    # Now uncompress it
    if tarball[:2] != GZIP_CONSTANT:
        raise ValueError("scexe file seems corrupt")

    tf = tarfile.open(name="bogus_name_for_old_python_versions", fileobj=BytesIO(tarball), mode='r:gz')
    filenames = [x for x in tf.getnames() if x.endswith('.bin')]
    orig_filename = filename
    if not filename or filename not in filenames:
        if len(filenames) != 1:
            raise ValueError("scexe file seems corrupt")
        if filename and filename.lower() != filenames[0].lower():
            raise ValueError("scexe file seems corrupt")
        filename = filenames[0]

    tf.extract(filename, path)
    if filename != filename.lower():
        os.rename(filename, filename.lower())
    return filename.lower()
