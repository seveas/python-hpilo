# (c) 2011-2020 Dennis Kaarsemaker <dennis@kaarsemaker.net>
# see COPYING for license details

__version__ = "4.4.1"

import codecs
import io
import os
import errno
import platform
import random
import re
import socket
import ssl
import subprocess
import sys
import types
import xml.etree.ElementTree as etree
import warnings
import hpilo_fw

PY3 = sys.version_info[0] >= 3
if PY3:
    import urllib.request as urllib2
    class Bogus(Exception): pass
    socket.sslerror = Bogus
    basestring = str
    from os import fsencode
else:
    import urllib2
    fsencode = lambda x: x

# Python 2.7.13 renamed PROTOCOL_SSLv23 to PROTOCOL_TLS
if not hasattr(ssl, 'PROTOCOL_TLS'):
    ssl.PROTOCOL_TLS = ssl.PROTOCOL_SSLv23

# Oh the joys of monkeypatching...
# - We need a CDATA element in set_security_msg, but ElementTree doesn't support it
# - We need to disable escaping of the PASSWORD attribute, because iLO doesn't
#   unescape it properly
def CDATA(text=None):
    element = etree.Element('![CDATA[')
    element.text = text
    return element

# Adding this tag to RIBCL scripts should make this hack unnecessary in newer
# iLO firmware versions. TODO: Check compatibility.
# <?ilo entity-processing="standard"?>
class DoNotEscapeMe(str):
    pass

etree._original_escape_attrib = etree._escape_attrib
def _escape_attrib(text, *args, **kwargs):
    if isinstance(text, DoNotEscapeMe):
        return str(text)
    else:
        return etree._original_escape_attrib(text, *args, **kwargs)
etree._escape_attrib = _escape_attrib

# Python 2.7 and 3
if hasattr(etree, '_serialize_xml'):
    etree._original_serialize_xml = etree._serialize_xml
    def _serialize_xml(write, elem, *args, **kwargs):
        if elem.tag == '![CDATA[':
            write("\n<%s%s]]>\n" % (elem.tag, elem.text))
            return
        return etree._original_serialize_xml(write, elem, *args, **kwargs)
    etree._serialize_xml = etree._serialize['xml'] = _serialize_xml
# Python 2.6, and non-stdlib ElementTree
elif hasattr(etree.ElementTree, '_write'):
    etree.ElementTree._orig_write = etree.ElementTree._write
    def _write(self, file, node, encoding, namespaces):
        if node.tag == '![CDATA[':
            file.write("\n<![CDATA[%s]]>\n" % node.text.encode(encoding))
        else:
            self._orig_write(file, node, encoding, namespaces)
    etree.ElementTree._write = _write
else:
    raise RuntimeError("Don't know how to monkeypatch XML serializer workarounds. Please report a bug at https://github.com/seveas/python-hpilo")

# We handle non-ascii characters in the returned XML by replacing them with XML
# character references. This likely results in bogus data, but avoids crashes.
# The iLO should never do this, but firmware bugs may cause it to do so.
def iloxml_replace(error):
    ret = ""
    for pos in range(error.start, len(error.object)):
        b = error.object[pos]
        if not isinstance(b, int):
            b = ord(b)
        if b < 128:
            break
        ret += u'?'
    warnings.warn("Invalid ascii data found: %s, replaced with %s" % (repr(error.object[error.start:pos]), ret), IloWarning)
    return (ret, pos)
codecs.register_error('iloxml_replace', iloxml_replace)

# Which protocol to use
ILO_RAW  = 1
ILO_HTTP = 2
ILO_LOCAL = 3

class IloErrorMeta(type):
    def __new__(cls, name, parents, attrs):
        if 'possible_messages' not in attrs:
            attrs['possible_messages'] = []
        if 'possible_codes' not in attrs:
            attrs['possible_codes'] = []
        klass = super(IloErrorMeta, cls).__new__(cls, name, parents, attrs)
        if name != 'IloError':
            IloError.known_subclasses.append(klass)
        return klass

class IloError(Exception):
    __metaclass__ = IloErrorMeta
    def __init__(self, message, errorcode=None):
        if issubclass(IloError, object):
            super(IloError, self).__init__(message)
        else:
            Exception.__init__(self, message)
        self.errorcode = errorcode
    known_subclasses = []

if PY3:
    # Python 3 ignores __metaclass__ but wants class foo(metaclass=bar) But
    # that syntax is an error on older python, so recreate IloError properly
    # the manual way.
    IloError = IloErrorMeta('IloError', (Exception,), {'known_subclasses': [], '__init__': IloError.__init__})

class IloCommunicationError(IloError):
    pass

class IloGeneratingCSR(IloError):
    possible_messages = ['The iLO subsystem is currently generating a Certificate Signing Request(CSR), run script after 10 minutes or more to receive the CSR.']
    possible_codes = [0x0088]

class IloLoginFailed(IloError):
    possible_messages = ['Login failed', 'Login credentials rejected']
    possible_codes = [0x005f]

class IloUserNotFound(IloError):
    possible_codes = [0x000a]

class IloPermissionError(IloError):
    possible_codes = [0x0023]

class IloNotARackServer(IloError):
    possible_codes = [0x002a]

class IloLicenseKeyError(IloError):
    possible_codes = [0x002e]

class IloFeatureNotSupported(IloError):
    possible_codes = [0x003c]

class IloNotConfigured(IloError):
    possible_codes = [0x006d]

class IloWarning(Warning):
    pass

class IloXMLWarning(Warning):
    pass

class IloTestWarning(Warning):
    pass

class Ilo(object):
    """Represents an iLO/iLO2/iLO3/iLO4/RILOE II management interface on a
        specific host. A new connection using the specified login, password and
        timeout will be made for each API call. The library will detect which
        protocol to use, but you can override this by setting protocol to
        ILO_RAW or ILO_HTTP. Use ILO_LOCAL to avoid using a network connection
        and use hponcfg instead. Username and password are ignored for ILO_LOCAL
        connections. Set delayed to True to make python-hpilo not send requests
        immediately, but group them together. See :func:`call_delayed`"""

    XML_HEADER = b'<?xml version="1.0"?>\r\n'
    HTTP_HEADER = b"POST /ribcl HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nConnection: Close%s\r\n\r\n"
    HTTP_UPLOAD_HEADER = b"POST /cgi-bin/uploadRibclFiles HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\nContent-Length: %d\r\nContent-Type: multipart/form-data; boundary=%s\r\n\r\n"
    BLOCK_SIZE = 64 * 1024

    def __init__(self, hostname, login=None, password=None, timeout=60, port=443, protocol=None, delayed=False, ssl_verify=False, ssl_context=None, ssl_version=None):
        self.hostname = hostname
        self.login    = login or 'Administrator'
        self.password = password or 'Password'
        self.timeout  = timeout
        self.debug    = 0
        self.port     = port
        self.protocol = protocol
        self.ssl_verify = False
        self.ssl_context = ssl_context
        self.cookie   = None
        self.delayed  = delayed
        self._elements = None
        self._processors = []
        self.save_response = None
        self.read_response = None
        self.save_request = None
        self._protect_passwords = os.environ.get('HPILO_DONT_PROTECT_PASSWORDS', None) != 'YesPlease'
        self.firmware_mirror = None
        self.hponcfg = "/sbin/hponcfg"
        hponcfg = 'hponcfg'
        if platform.system() == 'Windows':
            self.hponcfg = 'C:\Program Files\HP Lights-Out Configuration Utility\cpqlocfg.exe'
            hponcfg = 'cpqlocfg.exe'
        for path in os.environ.get('PATH','').split(os.pathsep):
            maybe = os.path.join(path, hponcfg)
            if os.access(maybe, os.X_OK):
                self.hponcfg = maybe
                break
        if self.ssl_verify:
            if sys.version_info < (2,7,9):
                raise EnvironmentError("SSL verification only works with python 2.7.9 or newer")
            if not self.ssl_context:
                self.ssl_context = ssl.create_default_context()
                # Sadly, ancient iLO's aren't dead yet, so let's enable sslv3 by default
                self.ssl_context.options &= ~ssl.OP_NO_SSLv3

    def __str__(self):
        return "iLO interface of %s" % self.hostname

    def _debug(self, level, message):
        if message.__class__.__name__ == 'bytes':
            message = message.decode('ascii')
        if self.debug >= level:
            if self._protect_passwords:
                message = re.sub(r'PASSWORD=".*?"', 'PASSWORD="********"', message)
            sys.stderr.write(message)
            if message.startswith('\r'):
                sys.stderr.flush()
            else:
                sys.stderr.write('\n')

    def _request(self, xml, progress=None):
        """Given an ElementTree.Element, serialize it and do the request.
           Returns an ElementTree.Element containing the response"""
        if not self.protocol and not self.read_response:
            self._detect_protocol()

        # Serialize the XML
        if hasattr(etree, 'tostringlist'):
            xml = b"\r\n".join(etree.tostringlist(xml)) + b'\r\n'
        else:
            xml = etree.tostring(xml)

        header, data =  self._communicate(xml, self.protocol, progress=progress)

        # This thing usually contains multiple XML messages
        messages = []
        while data:
            pos = data.find('<?xml', 5)
            if pos == -1:
                message = self._parse_message(data)
                data = None
            else:
                message = self._parse_message(data[:pos])
                data = data[pos:]

            # _parse_message returns None if a message has no useful content
            if message is not None:
                messages.append(message)

        if not messages:
            return header, None
        elif len(messages) == 1:
            return header, messages[0]
        else:
            return header, messages

    def _detect_protocol(self):
        # Use hponcfg when 'connecting' to localhost
        if self.hostname == 'localhost':
            self.protocol = ILO_LOCAL
            return
        # Do a bogus request, using the HTTP protocol. If there is no
        # header (see special case in communicate(), we should be using the
        # raw protocol
        header, data = self._communicate(b'<RIBCL VERSION="2.0"></RIBCL>', ILO_HTTP, save=False)
        if header:
            self.protocol = ILO_HTTP
        else:
            self.protocol = ILO_RAW

    def _upload_file(self, filename, progress):
        with open(filename, 'rb') as fd:
            firmware = fd.read()
        boundary = b'------hpiLO3t%dz' % random.randint(100000,1000000)
        while boundary in firmware:
            boundary = b'------hpiLO3t%dz' % str(random.randint(100000,1000000))
        parts = [
            b"""--%s\r\nContent-Disposition: form-data; name="fileType"\r\n\r\n""" % boundary,
            b"""\r\n--%s\r\nContent-Disposition: form-data; name="fwimgfile"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n""" % (boundary, fsencode(filename)),
            firmware,
            b"\r\n--%s--\r\n" % boundary,
        ]
        total_bytes = sum([len(x) for x in parts])
        sock = self._get_socket()

        self._debug(2, self.HTTP_UPLOAD_HEADER % (total_bytes, boundary))
        sock.write(self.HTTP_UPLOAD_HEADER % (total_bytes, boundary))
        for part in parts:
            if len(part) < self.BLOCK_SIZE:
                self._debug(2, part)
                sock.write(part)
            else:
                sent = 0
                fwlen = len(part)
                while sent < fwlen:
                    written = sock.write(part[sent:sent+self.BLOCK_SIZE])
                    if written is None:
                        plen = len(part[sent:sent+self.BLOCK_SIZE])
                        raise IloCommunicationError("Unexpected EOF while sending %d bytes (%d of %d sent before)" % (plen, sent, fwlen))

                    sent += written
                    if callable(progress):
                        progress("Sending request %d/%d bytes (%d%%)" % (sent, fwlen, 100.0*sent/fwlen))

        data = ''
        try:
            while True:
                d = sock.read()
                data += d.decode('ascii')
                if not d:
                    break
        except socket.sslerror as exc: # Connection closed
            if not data:
                raise IloCommunicationError("Communication with %s:%d failed: %s" % (self.hostname, self.port, str(exc)))

        self._debug(1, "Received %d bytes" % len(data))
        self._debug(2, data)
        if 'Set-Cookie:' not in data:
            # Seen on ilo3 with corrupt filesystem
            body = re.search('<body>(.*)</body>', data, flags=re.DOTALL).group(1)
            body = re.sub('<[^>]*>', '', body).strip()
            body = re.sub('Return to last page', '', body).strip()
            body = re.sub('\s+', ' ', body).strip()
            raise IloError(body)
        self.cookie = re.search('Set-Cookie: *(.*)', data).group(1)
        self._debug(2, "Cookie: %s" % self.cookie)

    def _get_socket(self):
        """Set up a subprocess or an https connection and do an HTTP/raw socket request"""
        if self.read_response or self.save_request:
            class FakeSocket(object):
                def __init__(self, rfile=None, wfile=None):
                    self.input = rfile and open(rfile, 'rb') or io.BytesIO()
                    self.output = wfile and open(wfile, 'ab') or io.BytesIO()
                    self.read = self.input.read
                    self.write = self.output.write
                    data = self.input.read(4)
                    self.input.seek(0)
                    self.protocol = data == b'HTTP' and ILO_HTTP or ILO_RAW
                def close(self):
                    self.input.close()
                    self.output.close()
                shutdown = lambda *args: None
            sock = FakeSocket(self.read_response, self.save_request)
            if self.read_response:
                self.protocol = sock.protocol
            return sock

        if self.protocol == ILO_LOCAL:
            self._debug(1, "Launching hponcfg")
            try:
                sp = subprocess.Popen([self.hponcfg, '--input', '--xmlverbose'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except OSError as exc:
                raise IloCommunicationError("Cannot run %s: %s" % (self.hponcfg, str(exc)))
            sp.write = sp.stdin.write
            sp.read = sp.stdout.read
            return sp

        self._debug(1, "Connecting to %s port %d" % (self.hostname, self.port))
        err = None
        for res in socket.getaddrinfo(self.hostname, self.port, 0, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            sock = None
            try:
                sock = socket.socket(af, socktype, proto)
                sock.settimeout(self.timeout)
                self._debug(2, "Connecting to %s port %d" % sa[:2])
                sock.connect(sa)
            except socket.timeout:
                if sock is not None:
                    sock.close()
                err = IloCommunicationError("Timeout connecting to %s port %d" % (self.hostname, self.port))
            except socket.error as exc:
                if sock is not None:
                    sock.close()
                err = IloCommunicationError("Error connecting to %s port %d: %s" % (self.hostname, self.port, str(exc)))

        if err is not None:
            raise err

        if not sock:
            raise IloCommunicationError("Unable to resolve %s" % self.hostname)

        try:
            if not self.ssl_context:
                self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
                # Even more sadly, some iLOs are still using RC4-SHA
                # which was dropped from the default cipher suite in
                # Python 2.7.10 and Python 3.4.4. Add it back here :(
                self.ssl_context.set_ciphers("RC4-SHA:" + ssl._DEFAULT_CIPHERS)
            return self.ssl_context.wrap_socket(
                sock, server_hostname=self.hostname)
        except ssl.SSLError as exc:
            raise IloCommunicationError("Cannot establish ssl session with %s:%d: %s" % (self.hostname, self.port, str(exc)))

    def _communicate(self, xml, protocol, progress=None, save=True):
        sock = self._get_socket()
        if self.read_response:
            protocol = sock.protocol
        msglen = len(self.XML_HEADER + xml)
        if protocol == ILO_HTTP:
            extra_header = b''
            if self.cookie:
                extra_header = b"\r\nCookie: %s" % self.cookie.encode('ascii')
            http_header = self.HTTP_HEADER % (msglen, extra_header)
            msglen += len(http_header)
        self._debug(1, "Sending XML request, %d bytes" % msglen)

        if protocol == ILO_HTTP:
            self._debug(2, http_header)
            sock.write(http_header)

        self._debug(2, self.XML_HEADER + xml)

        # XML header and data need to arrive in 2 distinct packets
        if self.protocol != ILO_LOCAL:
            sock.write(self.XML_HEADER)
        if b'$EMBED' in xml:
            pre, name, post = re.compile(b'(.*)\$EMBED:(.*)\$(.*)', re.DOTALL).match(xml).groups()
            sock.write(pre)
            sent = 0
            fwlen = os.path.getsize(name)
            with open(name, 'rb') as fd:
                fw = fd.read()
            while sent < fwlen:
                written = sock.write(fw[sent:sent+self.BLOCK_SIZE])
                sent += written
                if callable(progress):
                    progress("Sending request %d/%d bytes (%d%%)" % (sent, fwlen, 100.0*sent/fwlen))
            sock.write(post.strip())
        else:
            sock.write(xml)

        # And grab the data
        if self.save_request and save:
            sock.close()
            return None, None
        if self.protocol == ILO_LOCAL:
            # hponcfg doesn't return data until stdin is closed
            sock.stdin.close()
        data = ''
        try:
            while True:
                d = sock.read().decode('ascii', 'iloxml_replace')
                data += d
                if not d:
                    break
                if callable(progress) and d.strip().endswith('</RIBCL>'):
                    d = d[d.find('<?xml'):]
                    while '<?xml' in d:
                        end = d.find('<?xml', 5)
                        if end == -1:
                            msg = self._parse_message(d, include_inform=True)
                            if msg:
                                progress(msg)
                            break
                        else:
                            msg = self._parse_message(d[:end], include_inform=True)
                            if msg:
                                progress(msg)
                            d = d[end:]
        except socket.sslerror as exc: # Connection closed
            if not data:
                raise IloCommunicationError("Communication with %s:%d failed: %s" % (self.hostname, self.port, str(exc)))

        self._debug(1, "Received %d bytes" % len(data))
        if self.protocol == ILO_LOCAL:
            sock.stdout.close()
            sock.wait()
        elif sock.shutdown:
            # On OSX this may cause an ENOTCONN, Linux/Windows ignore that situation
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except socket.error as exc:
                if exc.errno == errno.ENOTCONN:
                    pass
                else:
                    raise
            sock.close()

        # Stript out garbage from hponcfg
        if self.protocol == ILO_LOCAL:
            data = data[data.find('<'):data.rfind('>')+1]

        if self.save_response and save:
            with open(self.save_response, 'a') as fd:
                fd.write(data)

        # Do we have HTTP?
        header_ = ''
        if protocol == ILO_HTTP and data.startswith('HTTP/1.1 200'):
            header, data = data.split('\r\n\r\n', 1)
            header_ = header
            header = [x.split(':', 1) for x in header.split('\r\n')[1:]]
            header = dict([(x[0].lower(), x[1].strip()) for x in header])
            if header['transfer-encoding'] == 'chunked':
                _data, data = data, ''
                while _data:
                    clen, _data = _data.split('\r\n', 1)
                    clen = int(clen, 16)
                    if clen == 0:
                        break
                    data += _data[:clen]
                    _data = _data[clen+2:]

        elif data.startswith('HTTP/1.1 404'):
            # We must be using iLO2 or older, they don't do HTTP for XML requests
            # This case is only triggered by the protocol detection
            header = None

        elif not data.startswith('<?xml'):
            if protocol == ILO_LOCAL:
                raise IloError(sock.stderr.read().strip())
            raise IloError("Remote returned bogus data, maybe it's not an iLO")

        else:
            header = None

        self._debug(2, "%s\r\n\r\n%s" % (header_, data))
        return header, data


    def _root_element(self, element, **attrs):
        """Create a basic XML structure for a message. Return root and innermost element"""
        if not self.delayed or not self._elements:
            root = etree.Element('RIBCL', VERSION="2.0")
            login = etree.SubElement(root, 'LOGIN', USER_LOGIN=self.login, PASSWORD=DoNotEscapeMe(self.password))
        if self.delayed:
            if self._elements:
                root, login = self._elements
            else:
                self._elements = (root, login)
        if self.delayed and len(login) and login[-1].tag == element and login[-1].attrib == attrs:
            element = login[-1]
        else:
            element = etree.SubElement(login, element, **attrs)
        return root, element

    def _attempt_to_fix_broken_xml(self, data):
        """ Many iLO versions have bugs that causes them to emit malformed XML.
        This is a collection of workarounds and kludges to try and fix up the
        data so ElementTree has a chance to parse it correctly"""

        warnings.warn("iLO returned malformed XML, attempting to fix. Please contact HP to report a bug", IloXMLWarning)

        if '<RIBCL VERSION="2.22"/>' in data:
            data = data.replace('<RIBCL VERSION="2.22"/>', '<RIBCL VERSION="2.22">')
        # Quite a few unescaped quotation mark bugs keep appearing. Let's try
        # to fix up the XML by replacing the last occurence of a quotation mark
        # *before* the position of the error.
        #
        # Definitely not an optimal algorithm, but this is not a hot path.
        # Let's favour correctness over hacks.
        last_position = None
        position = (0, 0)
        while position != last_position:
            last_position = position
            try:
                return etree.fromstring(data)
            except etree.ParseError as e:
                position = e.position
                x = position[0]-1
                y = position[1]
                lines = data.splitlines()
                y = lines[x].rfind('"', 0, y)
                lines[x] = lines[x][:y] + '&quot;' + lines[x][y+1:]
                data = '\n'.join(lines)
        # Couldn't fix it :(
        raise

    def _parse_message(self, data, include_inform=False):
        """Parse iLO responses into Element instances and remove useless messages"""
        data = data.strip()
        if not data:
            return None
        try:
            message = etree.fromstring(data)
        except etree.ParseError:
            message = self._attempt_to_fix_broken_xml(data)
        if message.tag == 'RIBCL':
            for child in message:
                if child.tag == 'INFORM':
                    if include_inform:
                        # Filter useless message:
                        if 'should be updated' in child.text:
                            return None
                        return child.text
                # RESPONSE with status 0 also adds no value
                # Maybe start adding <?xmlilo output-format="xml"?> to requests. TODO: check compatibility
                elif child.tag == 'RESPONSE' and int(child.get('STATUS'), 16) == 0:
                    if child.get('MESSAGE') != 'No error':
                        warnings.warn(child.get('MESSAGE'), IloWarning)
                # These are interesting, something went wrong
                elif child.tag == 'RESPONSE':
                    if 'syntax error' in child.get('MESSAGE') and not self.protocol:
                        # This is triggered when doing protocol detection, ignore
                        pass
                    else:
                        status = int(child.get('STATUS'), 16)
                        message = child.get('MESSAGE')
                        if 'syntax error' in message:
                            message += '. You may have tried to use a feature this iLO version or firmware version does not support.'
                        for subclass in IloError.known_subclasses:
                            if status in subclass.possible_codes or message in subclass.possible_messages:
                                raise subclass(message, status)
                        raise IloError(message, status)
                # And this type of message is the actual payload.
                else:
                    return message
            return None
        # This shouldn't be reached as all messages are RIBCL messages. But who knows!
        return message

    def _element_children_to_dict(self, element):
        """Returns a dict with tag names of all child elements as keys and the
           VALUE attributes as values"""
        retval = {}
        keys = [elt.tag.lower() for elt in element]
        if len(keys) != 1 and len(set(keys)) == 1:
            # Can't return a dict
            retval = []
        for elt in element:
            # There are some special tags
            fname =  '_parse_%s_%s' % (element.tag.lower(), elt.tag.lower())
            if hasattr(self, fname):
                retval.update(getattr(self, fname)(elt))
                continue
            key, val, unit, description = elt.tag.lower(), elt.get('VALUE', elt.get('value', None)), elt.get('UNIT', None), elt.get('DESCRIPTION', None)
            if val is None:
                # HP is not best friends with consistency. Sometimes there are
                # attributes, sometimes child tags and sometimes text nodes. Oh
                # well, deal with it :)
                if element.tag.lower() == 'rimp' or elt.tag.lower() in self.xmldata_ectd.get(element.tag.lower(), []) or elt.tag.lower() == 'temps':
                    val = self._element_children_to_dict(elt)
                elif elt.attrib and list(elt):
                    val = self._element_to_dict(elt)
                elif list(elt):
                    val = self._element_to_list(elt)
                elif elt.text:
                    val = elt.text.strip()
                elif elt.attrib:
                    val = self._element_to_dict(elt)

            val = self._coerce(val)
            if unit:
                val = (val, unit)
            if description and isinstance(val, str):
                val = (val, description)
            if isinstance(retval, list):
                retval.append(val)
            elif key in retval:
                if isinstance(retval[key], dict):
                    retval[key].update(val)
                elif not isinstance(retval[key], list):
                    retval[key] = [retval[key], val]
                else:
                    retval[key].append(val)
            else:
                retval[key] = val
        return retval

    def _element_to_dict(self, element):
        """Returns a dict with tag attributes as items"""
        retval = {}
        for key, val in element.attrib.items():
            retval[key.lower()] = self._coerce(val)
        if list(element):
            fields = []
            for child in element.getchildren():
                if child.tag == 'FIELD':
                    fields.append(self._element_to_dict(child))
            if fields:
                names = [x['name'] for x in fields]
                if len(names) == len(set(names)):
                    # Field names are unique, treat them like attributes
                    for field in fields:
                        retval[field['name']] = field['value']
                else:
                    # Field names are not unique, such as the name "MAC"
                    retval['fields'] = fields
        return retval

    def _element_to_list(self, element):
        tagnames = [x.tag for x in element]
        if len(set(tagnames)) == 1:
            return [self._element_children_to_dict(x) for x in element]
        else:
            return [(child.tag.lower(), self._element_to_dict(child)) for child in element]

    def _coerce(self, val):
        """Do some data type coercion: unquote, turn integers into integers and
           Y/N into booleans"""
        if isinstance(val, basestring):
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            if val.isdigit():
                val = int(val)
            else:
                val = {'Y': True, 'N': False, 'true': True, 'false': False}.get(val, val)
        return val

    def _raw(self, *tags):
        if self.delayed:
            raise IloError("Cannot use raw tags in delayed mode")
        root, inner = self._root_element(tags[0][0], **(tags[0][1]))
        for t in tags[1:]:
            inner = etree.SubElement(inner, t[0], **t[1])
        header, message = self._request(root)
        fd = io.BytesIO()
        etree.ElementTree(message).write(fd)
        ret = fd.getvalue()
        fd.close()
        return ret

    def _info_tag(self, infotype, tagname, returntags=None, attrib={}, process=lambda x: x):
        root, inner = self._root_element(infotype, MODE='read')
        etree.SubElement(inner, tagname, **attrib)
        if self.delayed:
            self._processors.append([self._process_info_tag, returntags or [tagname], process])
            return
        header, message = self._request(root)
        if self.save_request:
            return
        return self._process_info_tag(message, returntags or [tagname], process)

    def _process_info_tag(self, message, returntags, process):
        if isinstance(returntags, basestring):
            returntags = [returntags]

        for tag in returntags:
            if message.find(tag) is None:
                continue
            message = message.find(tag)
            if list(message):
                return process(self._element_children_to_dict(message))
            else:
                return process(self._element_to_dict(message))
        raise IloError("Expected tag '%s' not found" % "' or '".join(returntags))

    def _control_tag(self, controltype, tagname, returntag=None, attrib={}, elements=[], text=None):
        root, inner = self._root_element(controltype, MODE='write')
        inner = etree.SubElement(inner, tagname, **attrib)
        if text:
            inner.text = text
        for element in elements:
            inner.append(element)
        if self.delayed:
            if tagname == 'CERTIFICATE_SIGNING_REQUEST':
                self._processors.append([self._process_control_tag, returntag or tagname])
            return
        header, message = self._request(root)
        return self._process_control_tag(message, returntag or tagname)

    def _process_control_tag(self, message, returntag):
        if message is None:
            return None
        message = message.find(returntag)
        if message.text.strip():
            return message.text.strip()
        if not message.attrib and not list(message):
            return None
        raise IloError("You've reached unknown territories, please report a bug")
        if list(message):
            return self._element_children_to_dict(message)
        else:
            return self._element_to_dict(message)

    def call_delayed(self):
        """In delayed mode, calling a method on an iLO object will not cause an
           immediate callout to the iLO. Instead, the method and parameters are
           stored for future calls of this method. This method makes one
           connection to the iLO and sends all commands as one XML document.
           This speeds up applications that make many calls to the iLO by
           removing seconds of overhead per call.

           The return value of call_delayed is a list of return values for
           individual methods that don't return None. This means that there may
           be fewer items returned than methods called as only `get_*` methods
           return data

           Delayed calls only work on iLO 2 or newer"""

        if not self._elements:
            raise ValueError("No commands scheduled")
        try:
            root, inner = self._elements
            header, message = self._request(root)
            ret = []
            if message is not None:
                if not isinstance(message, list):
                    message = [message]
                for message, processor in zip(message, self._processors):
                    ret.append(processor.pop(0)(message, *processor))
        finally:
            self._processors = []
            self._elements = None
        return ret

    def abort_dir_test(self):
        """Abort authentication directory test"""
        return self._control_tag('DIR_INFO', 'ABORT_DIR_TEST')

    def activate_license(self, key):
        """Activate an iLO advanced license"""
        license = etree.Element('ACTIVATE', KEY=key)
        return self._control_tag('RIB_INFO', 'LICENSE', elements=[license])

    def add_federation_group(self, group_name, group_key, admin_priv=False,
            remote_cons_priv=True, reset_server_priv=False,
            virtual_media_priv=False, config_ilo_priv=True, login_priv=False):
        """Add a new federation group"""
        attrs = locals()
        elements = []
        for attribute in [x for x in attrs.keys() if x.endswith('_priv')]:
            val = ['No', 'Yes'][bool(attrs[attribute])]
            elements.append(etree.Element(attribute.upper(), VALUE=val))

        return self._control_tag('RIB_INFO', 'ADD_FEDERATION_GROUP', elements=elements,
                attrib={'GROUP_NAME': group_name, 'GROUP_KEY': group_key})

    def add_sso_server(self, server=None, import_from=None, certificate=None):
        """Add an SSO server by name (only if SSO trust level is lowered) or by
           importing a certificate from a server or directly"""
        if [server, import_from, certificate].count(None) != 2:
            raise ValueError("You must specify exactly one of server, import_from or certificate")
        if server:
            return self._control_tag('SSO_INFO', 'SSO_SERVER', attrib={'NAME': server})
        if import_from:
            return self._control_tag('SSO_INFO', 'SSO_SERVER', attrib={'IMPORT_FROM': import_from})
        if certificate:
            return self._control_tag('SSO_INFO', 'IMPORT_CERTIFICATE', text=certificate)

    def add_user(self, user_login, user_name, password, admin_priv=False,
            remote_cons_priv=True, reset_server_priv=False,
            virtual_media_priv=False, config_ilo_priv=True):
        """Add a new user to the iLO interface with the specified name,
           password and permissions. Permission attributes should be boolean
           values."""
        attrs = locals()
        elements = []
        for attribute in [x for x in attrs.keys() if x.endswith('_priv')]:
            val = ['No', 'Yes'][bool(attrs[attribute])]
            elements.append(etree.Element(attribute.upper(), VALUE=val))

        return self._control_tag('USER_INFO', 'ADD_USER', elements=elements,
                attrib={'USER_LOGIN': user_login, 'USER_NAME': user_name, 'PASSWORD': DoNotEscapeMe(password)})

    def ahs_clear_data(self):
        """Clears Active Health System information log"""
        return self._control_tag('RIB_INFO', 'AHS_CLEAR_DATA')

    def cert_fqdn(self, use_fqdn):
        """Configure whether to use the fqdn or the short hostname for certificate requests"""
        use_fqdn = str({True: 'Yes', False: 'No'}.get(use_fqdn, use_fqdn))
        return self._control_tag('RIB_INFO', 'CERT_FQDN', attrib={'VALUE': use_fqdn})

    def certificate_signing_request(self, country=None, state=None, locality=None, organization=None,
            organizational_unit=None, common_name=None):
        """Get a certificate signing request from the iLO"""
        vars = locals()
        del vars['self']
        vars = [('CSR_' + x.upper(), vars[x]) for x in vars if vars[x]]
        elements = map(lambda x: etree.Element(x[0], attrib={'VALUE': str(x[1])}), vars)
        return self._control_tag('RIB_INFO', 'CERTIFICATE_SIGNING_REQUEST', elements=elements)

    def clear_ilo_event_log(self):
        """Clears the iLO event log"""
        return self._control_tag('RIB_INFO', 'CLEAR_EVENTLOG')

    def clear_server_event_log(self):
        """Clears the server event log"""
        return self._control_tag('SERVER_INFO', 'CLEAR_IML')

    def clear_server_power_on_time(self):
        """Clears the server power on time"""
        return self._control_tag('SERVER_INFO', 'CLEAR_SERVER_POWER_ON_TIME')

    def computer_lock_config(self, computer_lock=None, computer_lock_key=None):
        """Configure the computer lock settings"""
        if computer_lock_key:
            computer_lock = "custom"
        if not computer_lock:
            raise ValueError("A value must be specified for computer_lock")
        elements = [etree.Element('COMPUTER_LOCK', VALUE=computer_lock)]
        if computer_lock_key:
            elements.append(etree.Element('COMPUTER_LOCK_KEY', VALUE=computer_lock_key))
        return self._control_tag('RIB_INFO', 'COMPUTER_LOCK_CONFIG', elements=elements)

    def dc_registration_complete(self):
        """Complete the ERS registration of your device after calling
           set_ers_direct_connect"""
        return self._control_tag('RIB_INFO', 'DC_REGISTRATION_COMPLETE')

    def delete_federation_group(self, group_name):
        """Delete the specified federation group membership"""
        return self._control_tag('RIB_INFO', 'DELETE_FEDERATION_GROUP', attrib={'GROUP_NAME': group_name})

    def delete_sso_server(self, index):
        """Delete an SSO server by index"""
        return self._control_tag('SSO_INFO', 'DELETE_SERVER',
                                 attrib={'INDEX': str(index)})

    def delete_user(self, user_login):
        """Delete the specified user from the ilo"""
        return self._control_tag('USER_INFO', 'DELETE_USER', attrib={'USER_LOGIN': user_login})

    def deactivate_license(self):
        """Delete the license key from the iLO"""
        element = etree.Element('DEACTIVATE')
        return self._control_tag('RIB_INFO', 'LICENSE', elements=[element])

    def disable_ers(self):
        """Disable Insight Remote Support functionality and unregister the server"""
        return self._control_tag('RIB_INFO', 'DISABLE_ERS')

    def eject_virtual_floppy(self):
        """Eject the virtual floppy"""
        return self._control_tag('RIB_INFO', 'EJECT_VIRTUAL_FLOPPY')

    def eject_virtual_media(self, device="cdrom"):
        """Eject the virtual media attached to the specified device"""
        return self._control_tag('RIB_INFO', 'EJECT_VIRTUAL_MEDIA',
                attrib={"DEVICE": device.upper()})

    def ers_ahs_submit(self, message_id, bb_days):
        """Submity AHS data to the insight remote support server"""
        elements = [
            etree.Element('MESSAGE_ID', attrib={'VALUE': str(message_id)}),
            etree.Element('BB_DAYS', attrib={'VALUE': str(bb_days)}),
        ]
        return self._control_tag('RIB_INFO', 'TRIGGER_BB_DATA', elements=elements)

    def fips_enable(self):
        """Enable FIPS standard to enforce AES/3DES encryption, can only be
           reset with a call to factory_defaults. Resets Administrator password
           and license key"""
        return self._control_tag('RIB_INFO', 'FIPS_ENABLE')

    def factory_defaults(self):
        """Reset the iLO to factory default settings"""
        return self._control_tag('RIB_INFO', 'FACTORY_DEFAULTS')

    def force_format(self):
        """Forcefully format the iLO's internal NAND flash. Only use this when
           the iLO is having severe problems and its self-test fails"""
        return self._control_tag('RIB_INFO', 'FORCE_FORMAT', attrib={'VALUE': 'all'})

    def get_ahs_status(self):
        """Get active health system logging status"""
        return self._info_tag('RIB_INFO', 'GET_AHS_STATUS')

    def get_all_users(self):
        """Get a list of all loginnames"""
        def process(data):
            if isinstance(data, dict):
                data = data.values()
            return [x for x in data if x]

        return self._info_tag('USER_INFO', 'GET_ALL_USERS', process=process)

    def get_all_user_info(self):
        """Get basic and authorization info of all users"""
        def process(data):
            if isinstance(data, dict):
                data = data.values()
            return dict([(x['user_login'], x) for x in data])
        return self._info_tag('USER_INFO', 'GET_ALL_USER_INFO', process=process)

    def get_asset_tag(self):
        """Gets the server asset tag"""
        # The absence of an asset tag is communicated in a warning and there
        # will be *NO* returntag, hence the AttributeError.
        try:
            return self._info_tag('SERVER_INFO', 'GET_ASSET_TAG')
        except AttributeError:
            return {'asset_tag': None}

    def get_cert_subject_info(self):
        """Get ssl certificate subject information"""
        return self._info_tag('RIB_INFO', 'GET_CERT_SUBJECT_INFO', 'CSR_CERT_SETTINGS')

    def get_critical_temp_remain_off(self):
        """Get whether the server will remain powered off after a critical temperature shutdown"""
        return self._info_tag('SERVER_INFO', 'GET_CRITICAL_TEMP_REMAIN_OFF')

    def get_current_boot_mode(self):
        """Get the current boot mode (legaci or uefi)"""
        return self._info_tag('SERVER_INFO', 'GET_CURRENT_BOOT_MODE', process=lambda data: data['boot_mode'])

    def get_diagport_settings(self):
        """Get the blade diagport settings"""
        return self._info_tag('RACK_INFO', 'GET_DIAGPORT_SETTINGS')

    def get_dir_config(self):
        """Get directory authentication configuration"""
        return self._info_tag('DIR_INFO', 'GET_DIR_CONFIG')

    def get_dir_test_results(self):
        """Get the results of the authentication directory test"""
        def process(data):
            for item in data:
                data[item] = dict([(x[0], x[1]['value']) for x in data[item]])
            return data
        return self._info_tag('DIR_INFO', 'GET_DIR_TEST_RESULTS', process=process)

    def get_embedded_health(self):
        """Get server health information"""
        def process(data):
            for category in data:
                if category == 'health_at_a_glance':
                    health = {}
                    for key, val in data[category]:
                        if key not in health:
                            health[key] = val
                        else:
                            health[key].update(val)
                    data[category] = health
                    continue
                elif isinstance(data[category], list) and data[category]:
                    for tag in ('label', 'location'):
                        if tag in data[category][0]:
                            data[category] = dict([(x[tag], x) for x in data[category]])
                            break
                elif data[category] in ['', []]:
                    data[category] = None
            return data
        return self._info_tag('SERVER_INFO', 'GET_EMBEDDED_HEALTH', 'GET_EMBEDDED_HEALTH_DATA',
                process=process)

    # Ok, special XML structures. Yay.
    def _parse_get_embedded_health_data_drives(self, element):
        ret = []
        for bp in element:
            if bp.tag != 'BACKPLANE':
                raise IloError("Unexpected data returned: %s" % bp.tag)
            backplane =  obj = {'drive_bays': {}}
            ret.append(backplane)
            for elt in bp:
                if elt.tag == 'DRIVE_BAY':
                    obj = {}
                    backplane['drive_bays'][int(elt.get('VALUE'))] = obj
                else:
                    obj[elt.tag.lower()] = elt.get('VALUE')
        return {'drives_backplanes': ret}

    def _parse_get_embedded_health_data_memory(self, element):
        ret = {}
        for elt in element:
            fname =  '_parse_%s_%s' % (element.tag.lower(), elt.tag.lower())
            if hasattr(self, fname):
                ret.update(getattr(self, fname)(elt))
                continue
            ret[elt.tag.lower()] = self._element_children_to_dict(elt)
        return {element.tag.lower(): ret}
    _parse_memory_memory_details_summary = _parse_get_embedded_health_data_memory

    def _parse_memory_memory_details(self, element):
        ret = {}
        for elt in element:
            if elt.tag not in ret:
                ret[elt.tag] = {}
            data = self._element_children_to_dict(elt)
            ret[elt.tag]["socket %d" % data["socket"]] = data
        return {element.tag.lower(): ret}

    def _parse_get_embedded_health_data_nic_information(self, element):
        return {'nic_information': [self._element_children_to_dict(elt) for elt in element]}
    # Can you notice the misspelling?Yes, this is an actual bug in the HP firmware, seen in at least ilo3 1.70
    _parse_get_embedded_health_data_nic_infomation = _parse_get_embedded_health_data_nic_information

    def _parse_get_embedded_health_data_firmware_information(self, element):
        ret = {}
        for elt in element:
            data = self._element_children_to_dict(elt)
            ret[data['firmware_name']] = data['firmware_version']
        return {element.tag.lower(): ret}

    def _parse_get_embedded_health_data_storage(self, element):
        key = element.tag.lower()
        ret = {key: []}
        for ctrl in element:
            if ctrl.tag == 'DISCOVERY_STATUS':
                ret['%s_%s' % (key, ctrl.tag.lower())] = self._element_children_to_dict(ctrl)['status']
                continue
            data = {}
            for elt in ctrl:
                tag = elt.tag.lower()
                if tag in ('drive_enclosure', 'logical_drive'):
                    tag += 's'
                    if tag not in data:
                        data[tag] = []
                    if tag == 'drive_enclosures':
                        data[tag].append(self._element_children_to_dict(elt))
                    else:
                        data[tag].append(self._parse_logical_drive(elt))
                else:
                    data[tag] = elt.get('VALUE')
            ret[key].append(data)
        return ret

    def _parse_logical_drive(self, element):
        data = {}
        for elt in element:
            tag = elt.tag.lower()
            if tag == 'physical_drive':
                tag += 's'
                if tag not in data:
                    data[tag] = []
                data[tag].append(self._element_children_to_dict(elt))
            else:
                data[tag] = elt.get('VALUE')
        return data

    def _parse_get_embedded_health_data_power_supplies(self, element):
        key = element.tag.lower()
        ret = {key: {}}
        for elt in element:
            data = self._element_children_to_dict(elt)
            if 'label' in data:
                ret[key][data['label']] = data
            else:
                ret[elt.tag.lower()] = data
        return ret

    def get_enclosure_ip_settings(self):
        """Get the enclosure bay static IP settings"""
        return self._info_tag('RACK_INFO', 'GET_ENCLOSURE_IP_SETTINGS')

    def get_encrypt_settings(self):
        """Get the iLO encryption settings"""
        return self._info_tag('RIB_INFO', 'GET_ENCRYPT_SETTINGS')

    def get_ers_settings(self):
        """Get the ERS Insight Remote Support settings"""
        return self._info_tag('RIB_INFO', 'GET_ERS_SETTINGS')

    def get_federation_all_groups(self):
        """Get all federation group names"""
        def process(data):
            if isinstance(data, dict):
                data = data.values()
            return data
        return self._info_tag('RIB_INFO', 'GET_FEDERATION_ALL_GROUPS', process=process)

    def get_federation_all_groups_info(self):
        """Get all federation group names and associated privileges"""
        def process(data):
            if isinstance(data, dict):
                data = data.values()
            data = [dict([(key, {'yes': True, 'no': False}.get(val['value'].lower(), val['value'])) for (key, val) in group]) for group in data]
            return dict([(x['group_name'], x) for x in data])
        return self._info_tag('RIB_INFO', 'GET_FEDERATION_ALL_GROUPS_INFO', process=process)

    def get_federation_group(self, group_name):
        """Get privileges for a specific federation group"""
        def process(data):
            return dict([(key, {'yes': True, 'no': False}.get(val['value'].lower(), val['value'])) for (key, val) in data.values()[0]])
        return self._info_tag('RIB_INFO', 'GET_FEDERATION_GROUP', attrib={'GROUP_NAME': group_name}, process=process)

    def get_federation_multicast(self):
        """Get the iLO federation mulicast settings"""
        return self._info_tag('RIB_INFO', 'GET_FEDERATION_MULTICAST')

    def get_fips_status(self):
        """Is the FIPS-mandated AES/3DESencryption enforcement in place"""
        return self._info_tag('RIB_INFO', 'GET_FIPS_STATUS')

    def get_fw_version(self):
        """Get the iLO type and firmware version, use get_product_name to get the server model"""
        return self._info_tag('RIB_INFO', 'GET_FW_VERSION')

    def get_global_settings(self):
        """Get global iLO settings"""
        return self._info_tag('RIB_INFO', 'GET_GLOBAL_SETTINGS')

    def get_host_data(self, decoded_only=True):
        """Get SMBIOS records that describe the host. By default only the ones
           where human readable information is available are returned. To get
           all records pass :attr:`decoded_only=False` """

        def process(data):
            if decoded_only:
                data = [x for x in data if len(x) > 2]
            return data
        return self._info_tag('SERVER_INFO', 'GET_HOST_DATA', process=process)

    def get_host_power_reg_info(self):
        """Get power regulator information"""
        return self._control_tag('SERVER_INFO', 'GET_HOST_POWER_REG_INFO')

    def get_host_power_saver_status(self):
        """Get the configuration of the ProLiant power regulator"""
        return self._info_tag('SERVER_INFO', 'GET_HOST_POWER_SAVER_STATUS', 'GET_HOST_POWER_SAVER')

    def get_host_power_status(self):
        """Whether the server is powered on or not"""
        return self._info_tag('SERVER_INFO', 'GET_HOST_POWER_STATUS', 'GET_HOST_POWER',
                process=lambda data: data['host_power'])

    def get_host_pwr_micro_ver(self):
        """Get the version of the power micro firmware"""
        return self._info_tag('SERVER_INFO', 'GET_HOST_PWR_MICRO_VER',
                process=lambda data: data['pwr_micro']['version'])

    def get_ilo_event_log(self):
        """Get the full iLO event log"""
        def process(data):
            if isinstance(data, dict) and 'event' in data:
                return [data['event']]
            return data
        return self._info_tag('RIB_INFO', 'GET_EVENT_LOG', 'EVENT_LOG', process=process)

    def get_language(self):
        """Get the default language set"""
        return self._info_tag('RIB_INFO', 'GET_LANGUAGE')

    def get_all_languages(self):
        """Get the list of installed languages - broken because iLO returns invalid XML"""
        return self._info_tag('RIB_INFO', 'GET_ALL_LANGUAGES')

    def get_all_licenses(self):
        """Get a list of all license types and licenses"""
        def process(data):
            if not isinstance(data, list):
                data = data.values()
            return [dict([(x[0], x[1]['value']) for x in row]) for row in data]
        return self._info_tag('RIB_INFO', 'GET_ALL_LICENSES', process=process)

    def get_hotkey_config(self):
        """Retrieve hotkeys available for use in remote console sessions"""
        return self._info_tag('RIB_INFO', 'GET_HOTKEY_CONFIG')

    def get_network_settings(self):
        """Get the iLO network settings"""
        return self._info_tag('RIB_INFO', 'GET_NETWORK_SETTINGS')

    def get_oa_info(self):
        """Get information about the Onboard Administrator of the enclosing chassis"""
        return self._info_tag('BLADESYSTEM_INFO', 'GET_OA_INFO')

    def get_one_time_boot(self):
        """Get the one time boot state of the host"""
        # Inconsistency between iLO 2 and 3, let's fix that
        def process(data):
            if 'device' in data['boot_type']:
                data['boot_type'] = data['boot_type']['device']
            return data['boot_type'].lower()
        return self._info_tag('SERVER_INFO', 'GET_ONE_TIME_BOOT', ('ONE_TIME_BOOT', 'GET_ONE_TIME_BOOT'), process=process)

    def get_pending_boot_mode(self):
        """Get the pending boot mode (legaci or uefi)"""
        return self._info_tag('SERVER_INFO', 'GET_PENDING_BOOT_MODE', process=lambda data: data['boot_mode'])

    def get_persistent_boot(self):
        """Get the boot order of the host. For uEFI hosts (gen9+), this returns
           a list of tuples (name, description. For older host it returns a
           list of names"""
        def process(data):
            if isinstance(data, dict):
                data = list(data.items())
                data.sort(key=lambda x: x[1])
                return [x[0].lower() for x in data]
            elif isinstance(data[0], tuple):
                return data
            return [x.lower() for x in data]
        return self._info_tag('SERVER_INFO', 'GET_PERSISTENT_BOOT', ('PERSISTENT_BOOT', 'GET_PERSISTENT_BOOT'), process=process)

    def get_pers_mouse_keyboard_enabled(self):
        """Returns whether persistent mouse and keyboard are enabled"""
        return self._info_tag('SERVER_INFO', 'GET_PERS_MOUSE_KEYBOARD_ENABLED', process=lambda data: data['persmouse_enabled'])

    def get_power_cap(self):
        """Get the power cap setting"""
        return self._info_tag('SERVER_INFO', 'GET_POWER_CAP', process=lambda data: data['power_cap'])

    def get_power_readings(self):
        """Get current, min, max and average power readings"""
        return self._info_tag('SERVER_INFO', 'GET_POWER_READINGS')

    def get_product_name(self):
        """Get the model name of the server, use get_fw_version to get the iLO model"""
        return self._info_tag('SERVER_INFO', 'GET_PRODUCT_NAME', process=lambda data: data['product_name'])

    def get_pwreg(self):
        """Get the power and power alert threshold settings"""
        return self._info_tag('SERVER_INFO', 'GET_PWREG')

    def get_rack_settings(self):
        """Get the rack settings for an iLO"""
        return self._info_tag('RACK_INFO', 'GET_RACK_SETTINGS')

    def get_sdcard_status(self):
        """Get whether an SD card is connected to the server"""
        return self._info_tag('SERVER_INFO', 'GET_SDCARD_STATUS')

    def get_security_msg(self):
        """Retrieve the security message that is displayed on the login screen"""
        return self._info_tag('RIB_INFO', 'GET_SECURITY_MSG')

    def get_server_auto_pwr(self):
        """Get the automatic power on delay setting"""
        return self._info_tag('SERVER_INFO', 'GET_SERVER_AUTO_PWR', process=lambda data: data['server_auto_pwr'])

    def get_server_event_log(self):
        """Get the IML log of the server"""
        def process(data):
            if isinstance(data, dict) and 'event' in data:
                return [data['event']]
            return data
        return self._info_tag('SERVER_INFO', 'GET_EVENT_LOG', 'EVENT_LOG', process=process)

    def get_server_fqdn(self):
        """Get the fqdn of the server this iLO is managing"""
        return self._info_tag('SERVER_INFO', 'GET_SERVER_FQDN', 'SERVER_FQDN', process=lambda fqdn: fqdn['value'])

    def get_server_name(self):
        """Get the name of the server this iLO is managing"""
        return self._info_tag('SERVER_INFO', 'GET_SERVER_NAME', 'SERVER_NAME', process=lambda name: name['value'])

    def get_server_power_on_time(self):
        """How many minutes ago has the server been powered on"""
        return self._info_tag('SERVER_INFO', 'GET_SERVER_POWER_ON_TIME', 'SERVER_POWER_ON_MINUTES', process=lambda data: int(data['value']))

    def get_smh_fqdn(self):
        """Get the fqdn of the HP System Management Homepage"""
        return self._info_tag('SERVER_INFO', 'GET_SMH_FQDN', 'SMH_FQDN', process=lambda fqdn: fqdn['value'])

    def get_snmp_im_settings(self):
        """Where does the iLO send SNMP traps to and which traps does it send"""
        return self._info_tag('RIB_INFO', 'GET_SNMP_IM_SETTINGS')

    def get_spatial(self):
        """Get location information"""
        return self._info_tag('SERVER_INFO', 'GET_SPATIAL', 'SPATIAL')

    def get_sso_settings(self):
        """Get the HP SIM Single Sign-On settings"""
        return self._info_tag('SSO_INFO', 'GET_SSO_SETTINGS')

    def get_supported_boot_mode(self):
        return self._info_tag('SERVER_INFO', 'GET_SUPPORTED_BOOT_MODE', process=lambda data: data['supported_boot_mode'])

    def get_topology(self):
        """Get rack topology information"""
        return self._info_tag('RACK_INFO', 'GET_TOPOLOGY')

    def get_tpm_status(self):
        """Get the status of the Trusted Platform Module"""
        return self._info_tag('SERVER_INFO', 'GET_TPM_STATUS')

    def get_twofactor_settings(self):
        """Get two-factor authentication settings"""
        return self._info_tag('RIB_INFO', 'GET_TWOFACTOR_SETTINGS')

    def get_uid_status(self):
        """Get the status of the UID light"""
        return self._info_tag('SERVER_INFO', 'GET_UID_STATUS', process=lambda data: data['uid'])

    def get_user(self, user_login):
        """Get user info about a specific user"""
        return self._info_tag('USER_INFO', 'GET_USER', attrib={'USER_LOGIN': user_login})

    def get_vm_status(self, device="CDROM"):
        """Get the status of virtual media devices. Valid devices are FLOPPY and CDROM"""
        return self._info_tag('RIB_INFO', 'GET_VM_STATUS', attrib={'DEVICE': device})

    def hotkey_config(self, ctrl_t=None, ctrl_u=None, ctrl_v=None, ctrl_w=None,
                      ctrl_x=None, ctrl_y=None):
        """Change remote console hotkeys"""
        vars = locals()
        del vars['self']
        elements = [etree.Element(x.upper(), VALUE=vars[x]) for x in vars if vars[x] is not None]
        return self._control_tag('RIB_INFO', 'HOTKEY_CONFIG', elements=elements)

    def import_certificate(self, certificate):
        """Import a signed SSL certificate"""
        return self._control_tag('RIB_INFO', 'IMPORT_CERTIFICATE', text=certificate)

    # Broken in iLO3 < 1.55 for Administrator
    def import_ssh_key(self, user_login, ssh_key):
        """Imports an SSH key for the specified user. The value of ssh_key
           should be the content of an id_dsa.pub or id_rsa.pub file"""
        # Basic sanity checking
        if ' ' not in ssh_key:
            raise ValueError("Invalid SSH key")
        algo, key = ssh_key.split(' ',2)[:2]
        if algo not in ['ssh-dss', 'ssh-rsa']:
            raise ValueError("Invalid SSH key, only DSA and RSA keys are supported")
        try:
            key.decode('base64')
        except Exception:
            raise ValueError("Invalid SSH key")
        key_ = "-----BEGIN SSH KEY-----\r\n%s\r\n%s %s\r\n-----END SSH KEY-----\r\n" % (algo, key, user_login)
        return self._control_tag('RIB_INFO', 'IMPORT_SSH_KEY', text=key_)

    def delete_ssh_key(self, user_login):
        """Delete a users SSH key"""
        return self._control_tag('USER_INFO', 'MOD_USER', attrib={'USER_LOGIN': user_login}, elements=[etree.Element('DEL_USERS_SSH_KEY')])

    def insert_virtual_media(self, device, image_url):
        """Insert a virtual floppy or CDROM. Note that you will also need to
           use :func:`set_vm_status` to connect the media"""
        return self._control_tag('RIB_INFO', 'INSERT_VIRTUAL_MEDIA', attrib={'DEVICE': device.upper(), 'IMAGE_URL': image_url})

    def mod_encrypt_settings(self, user_login, password, ilo_group_name, cert_name, enable_redundancy,
            primary_server_address, primary_server_port, secondary_server_address=None, secondary_server_port=None):
        """Configure encryption settings"""
        vars = locals()
        del vars['self']
        elements = []
        for var in ['ilo_group_name', 'enable_redundancy']:
            if vars[var] is not None:
                elements.append(etree.Element(var.upper(), VALUE=vars.pop(var)))
        for var in vars:
            if vars[var] is not None:
                elements.append(etree.Element('ESKM_' + var.upper(), VALUE=vars[var]))
        return self._control_tag('RIB_INFO', 'MOD_ENCRYPT_SETTINGS', elements=elements)

    def mod_federation_group(self, group_name, new_group_name=None, group_key=None,
            admin_priv=None, remote_cons_priv=None, reset_server_priv=None,
            virtual_media_priv=None, config_ilo_priv=None, login_priv=None):
        """Set attributes for a federation group, only specified arguments will
           be changed.  All arguments except group_name, new_group_name and
           group_key should be boolean"""
        attrs = locals()
        elements = []
        if attrs['new_group_name'] is not None:
            elements.append(etree.Element('GROUP_NAME', VALUE=attrs['new_group_name']))
        if attrs['group_key'] is not None:
            elements.append(etree.Element('PASSWORD', VALUE=attrs['group_key']))
        for attribute in [x for x in attrs.keys() if x.endswith('_priv')]:
            if attrs[attribute] is not None:
                val = ['No', 'Yes'][bool(attrs[attribute])]
                elements.append(etree.Element(attribute.upper(), VALUE=val))
        return self._control_tag('RIB_INFO', 'MOD_FEDERATION_GROUP', attrib={'GROUP_NAME': group_name}, elements=elements)

    def mod_global_settings(self, ilo_funct_enabled=None, rbsu_post_ip=None,
            # Access settings
            f8_prompt_enabled=None, f8_login_required=None, lock_configuration=None,
            serial_cli_status=None, serial_cli_speed=None,
            http_port=None, https_port=None, ssh_port=None, ssh_status=None,
            ipmi_dcmi_over_lan_enabled=None, ipmi_dcmi_over_lan_port=None,
            remote_console_port_status=None, remote_console_port=None, remote_console_encryption=None,
            rawvsp_port=None, vsp_software_flow_control=None,
            terminal_services_port=None,
            shared_console_enable=None, shared_console_port=None, remote_console_acquire=None,
            telnet_enable=None, ssl_empty_records_enable=None,

            # Security settings
            min_password=None, enforce_aes=None, authentication_failure_logging=None,
            authentication_failure_delay_secs=None, authentication_failures_before_delay=None,
            ssl_v3_enable=None, session_timeout=None,

            # Monitoring & alerting
            snmp_access_enabled=None, snmp_port=None, snmp_trap_port=None,
            remote_syslog_enable=None, remote_syslog_server_address=None, remote_syslog_port=None,
            alertmail_enable=None, alertmail_email_address=None,
            alertmail_sender_domain=None, alertmail_smtp_server=None, alertmail_smtp_port=None,

            # Console capturing
            vsp_log_enable=None,
            interactive_console_replay_enable=None, console_capture_enable=None,
            console_capture_boot_buffer_enable=None, console_capture_fault_buffer_enable=None,
            console_capture_port=None,
            capture_auto_export_enable=None, capture_auto_export_location=None,
            capture_auto_export_username=None, capture_auto_export_password=None,

            # And the rest
            remote_keyboard_model=None, virtual_kbmouse_connection=None, vmedia_disable=None,
            virtual_media_port=None, key_up_key_down_enable=None, high_performance_mouse=None,
            brownout_recovery=None, enhanced_cli_prompt_enable=None, tcp_keep_alive_enable=None,
            propagate_time_to_host=None, passthrough_config=None):
        """Modify iLO global settings, only values that are specified will be changed. Note that
           many settings only work on certain iLO models and firmware versions"""
        vars = dict(locals())
        del vars['self']
        dont_map = ['authentication_failure_logging', 'authentication_failures_before_delay', 'serial_cli_speed']
        elements = [etree.Element(x.upper(), VALUE=str({True: 'Yes', False: 'No'}.get(vars[x], vars[x])))
                    for x in vars if vars[x] is not None and x not in dont_map] + \
                   [etree.Element(x.upper(), VALUE=str(vars[x]))
                    for x in vars if vars[x] is not None and x in dont_map]
        return self._control_tag('RIB_INFO', 'MOD_GLOBAL_SETTINGS', elements=elements)

    def mod_network_settings(self, enable_nic=None, reg_ddns_server=None,
            ping_gateway=None, dhcp_domain_name=None, speed_autoselect=None,
            nic_speed=None, full_duplex=None, dhcp_enable=None,
            ip_address=None, subnet_mask=None, gateway_ip_address=None,
            dns_name=None, domain_name=None, dhcp_gateway=None,
            dhcp_dns_server=None, dhcp_wins_server=None, dhcp_static_route=None,
            reg_wins_server=None, prim_dns_server=None, sec_dns_server=None,
            ter_dns_server=None, prim_wins_server=None, sec_wins_server=None,
            static_route_1=None, static_route_2=None, static_route_3=None,
            dhcp_sntp_settings=None, sntp_server1=None, sntp_server2=None,
            timezone=None, enclosure_ip_enable=None, web_agent_ip_address=None,
            shared_network_port=None, vlan_enabled=None, vlan_id=None,
            shared_network_port_vlan=None, shared_network_port_vlan_id=None, ipv6_address=None,
            ipv6_static_route_1=None, ipv6_static_route_2=None, ipv6_static_route_3=None,
            ipv6_prim_dns_server=None, ipv6_sec_dns_server=None, ipv6_ter_dns_server=None,
            ipv6_default_gateway=None, ipv6_preferred_protocol=None, ipv6_addr_autocfg=None,
            ipv6_reg_ddns_server=None, dhcpv6_dns_server=None, dhcpv6_rapid_commit=None,
            dhcpv6_stateful_enable=None, dhcpv6_stateless_enable=None, dhcpv6_sntp_settings=None,
            dhcpv6_domain_name=None, ilo_nic_auto_select=None, ilo_nic_auto_snp_scan=None,
            ilo_nic_auto_delay=None, ilo_nic_fail_over=None, gratuitous_arp=None,
            ilo_nic_fail_over_delay=None):
        """Configure the network settings for the iLO card. The static route arguments require
           dicts as arguments. The necessary keys in these dicts are dest,
           gateway and mask all in dotted-quad form"""
        vars = dict(locals())
        del vars['self']

        # For the ipv4 route elements, {'dest': XXX, 'gateway': XXX}
        # ipv6 routes are ipv6_dest, prefixlen, ipv6_gateway
        # IPv6 addresses may specify prefixlength as /64 (default 64)
        elements = [etree.Element(x.upper(), VALUE=str({True: 'Yes', False: 'No'}.get(vars[x], vars[x])))
                    for x in vars if vars[x] is not None and 'static_route_' not in x]
        for key in vars:
            if 'static_route_' not in key or not vars[key]:
                continue
            val = vars[key]
            # Uppercase all keys
            for key_ in val.keys():
                val[key_.upper()] = val.pop(key_)
            elements.append(etree.Element(key.upper(), **val))

        for element in elements:
            if element.tag == 'IPV6_ADDRESS':
                addr = element.attrib['VALUE']
                if '/' in addr:
                    addr, plen = addr.rsplit('/', 1)
                    element.attrib.update({'VALUE': addr, 'PREFIXLEN': plen})
                if 'PREFIXLEN' not in element.attrib:
                    element.attrib['PREFIXLEN'] = '64'
        return self._control_tag('RIB_INFO', 'MOD_NETWORK_SETTINGS', elements=elements)
    mod_network_settings.requires_dict = ['static_route_1', 'static_route_2', 'static_route_3',
        'ipv6_static_route_1', 'ipv6_static_route_2', 'ipv6_static_route_3']

    def mod_dir_config(self, dir_authentication_enabled=None,
            dir_local_user_acct=None,dir_server_address=None,
            dir_server_port=None,dir_object_dn=None,dir_object_password=None,
            dir_user_context_1=None,dir_user_context_2=None,
            dir_user_context_3=None,dir_user_context_4=None,
            dir_user_context_5=None,dir_user_context_6=None,
            dir_user_context_7=None,dir_user_context_8=None,
            dir_user_context_9=None,dir_user_context_10=None,
            dir_user_context_11=None,dir_user_context_12=None,
            dir_user_context_13=None,dir_user_context_14=None,
            dir_user_context_15=None,dir_enable_grp_acct=None,
            dir_kerberos_enabled=None,dir_kerberos_realm=None,
            dir_kerberos_kdc_address=None,dir_kerberos_kdc_port=None,
            dir_kerberos_keytab=None,
            dir_generic_ldap_enabled=None,
            dir_grpacct1_name=None,dir_grpacct1_sid=None,
            dir_grpacct1_priv=None,dir_grpacct2_name=None,
            dir_grpacct2_sid=None,dir_grpacct2_priv=None,
            dir_grpacct3_name=None,dir_grpacct3_sid=None,
            dir_grpacct3_priv=None,dir_grpacct4_name=None,
            dir_grpacct4_sid=None,dir_grpacct4_priv=None,
            dir_grpacct5_name=None,dir_grpacct5_sid=None,
            dir_grpacct5_priv=None,dir_grpacct6_name=None,
            dir_grpacct6_sid=None,dir_grpacct6_priv=None):
        """Modify iLO directory configuration, only values that are specified
             will be changed."""
        vars = dict(locals())
        del vars['self']

        # The _priv thing is a comma-separated list of numbers, but other
        # functions use names, and the iLO ssh interface shows different names.
        # Support them all.
        privmap = {
            'login':         1,
            'rc':            2,
            'remote_cons':   2,
            'vm':            3,
            'virtual_media': 3,
            'power':         4,
            'reset_server':  4,
            'config':        5,
            'config_ilo':    5,
            'admin':         6,
        }

        # create special case for element with text inside
        if dir_kerberos_keytab:
            keytab_el = etree.Element('DIR_KERBEROS_KEYTAB')
            keytab_el.text = dir_kerberos_keytab
            del vars['dir_kerberos_keytab']

        elements = []
        for key, val in vars.items():
            if val is None:
                continue
            if key.endswith('_priv'):
                if isinstance(val, basestring):
                    val = val.replace('oemhp_', '').replace('_priv', '').split(',')
                val = ','.join([str(privmap.get(x,x)) for x in val])
            else:
                val = str({True: 'Yes', False: 'No'}.get(val, val))
            elements.append(etree.Element(key.upper(), VALUE=val))

        if dir_kerberos_keytab:
            elements.append(keytab_el)
        return self._control_tag('DIR_INFO','MOD_DIR_CONFIG',elements=elements)


    def mod_snmp_im_settings(self, snmp_access=None, web_agent_ip_address=None,
            snmp_address_1=None, snmp_address_1_rocommunity=None, snmp_address_1_trapcommunity=None,
            snmp_address_2=None, snmp_address_2_rocommunity=None, snmp_address_2_trapcommunity=None,
            snmp_address_3=None, snmp_address_3_rocommunity=None, snmp_address_3_trapcommunity=None,
            snmp_port=None, snmp_trap_port=None, snmp_v3_engine_id=None, snmp_passthrough_status=None,
            trap_source_identifier=None, os_traps=None, rib_traps=None, cold_start_trap_broadcast=None,
            snmp_v1_traps=None, cim_security_mask=None, snmp_sys_location=None, snmp_sys_contact=None,
            agentless_management_enable=None, snmp_system_role=None, snmp_system_role_detail=None,
            snmp_user_profile_1=None, snmp_user_profile_2=None, snmp_user_profile_3=None):
        """Configure the SNMP and Insight Manager integration settings. The
           trapcommunity settings must be dicts with keys value (the name of
           the community) and version (1 or 2c)"""
        vars = dict(locals())
        del vars['self']
        elements = [etree.Element(x.upper(), VALUE=str({True: 'Yes', False: 'No'}.get(vars[x], vars[x])))
                    for x in vars if vars[x] is not None and 'trapcommunity' not in x and 'snmp_user_profile' not in x]
        for key in vars:
            if 'trapcommunity' in key and vars[key]:
                val = vars[key]
                for key_ in val.keys():
                    val[key_.upper()] = str(val.pop(key_))
                elements.append(etree.Element(key.upper(), **val))
            elif 'snmp_user_profile' in key and vars[key]:
                elt = etree.Element(key[:-2].upper(), {'INDEX': key[-1]})
                for key, val in vars[key].items():
                    etree.SubElement(elt, key.upper(), VALUE=str(val))
                elements.append(elt)
        return self._control_tag('RIB_INFO', 'MOD_SNMP_IM_SETTINGS', elements=elements)
    mod_snmp_im_settings.requires_dict = ['snmp_user_profile_1', 'snmp_user_profile_2', 'snmp_user_profile_3',
            'snmp_address_1_trapcommunity', 'snmp_address_2_trapcommunity', 'snmp_address_3_trapcommunity']

    def mod_sso_settings(self, trust_mode=None, user_remote_cons_priv=None,
            user_reset_server_priv=None, user_virtual_media_priv=None,
            user_config_ilo_priv=None, user_admin_priv=None,
            operator_login_priv=None, operator_remote_cons_priv=None,
            operator_reset_server_priv=None, operator_virtual_media_priv=None,
            operator_config_ilo_priv=None, operator_admin_priv=None,
            administrator_login_priv=None, administrator_remote_cons_priv=None,
            administrator_reset_server_priv=None, administrator_virtual_media_priv=None,
            administrator_config_ilo_priv=None, administrator_admin_priv=None):
        vars = dict(locals())
        del vars['self']
        del vars['trust_mode']
        elements = []
        if trust_mode is not None:
            elements.append(etree.Element('TRUST_MODE', attrib={'VALUE': trust_mode}))
        vars = [(x.upper().split('_', 1), {True: 'Yes', False: 'No'}.get(vars[x], vars[x])) for x in vars if vars[x]]
        elements += [etree.Element(x[0][0] + '_ROLE', attrib={x[0][1]: x[1]}) for x in vars]
        return self._control_tag('SSO_INFO', 'MOD_SSO_SETTINGS', elements=elements)

    def mod_twofactor_settings(self, auth_twofactor_enable=None, cert_revocation_check=None, cert_owner_san=None, cert_owner_subject=None):
        """Modify the twofactor authenticatino settings"""
        elements = []
        if auth_twofactor_enable is not None:
            elements.append(etree.Element('AUTH_TWOFACTOR_ENABLE', VALUE=['No', 'Yes'][bool(auth_twofactor_enable)]))
        if cert_revocation_check is not None:
            elements.append(etree.Element('CERT_REVOCATION_CHECK', VALUE=['No', 'Yes'][bool(cert_revocation_check)]))
        if cert_owner_san:
            elements.append(etree.Element('CERT_OWNER_SAN'))
        if cert_owner_subject:
            elements.append(etree.Element('CERT_OWNER_SUBJECT'))
        return self._control_tag('RIB_INFO', 'MOD_TWOFACTOR_SETTINGS', elements=elements)


    def mod_user(self, user_login, user_name=None, password=None,
            admin_priv=None, remote_cons_priv=None, reset_server_priv=None,
            virtual_media_priv=None, config_ilo_priv=None):
        """Set attributes for a user, only specified arguments will be changed.
           All arguments except user_name and password should be boolean"""

        attrs = locals()
        elements = []
        if attrs['user_name'] is not None:
            elements.append(etree.Element('USER_NAME', VALUE=attrs['user_name']))
        if attrs['password'] is not None:
            elements.append(etree.Element('PASSWORD', VALUE=DoNotEscapeMe(attrs['password'])))
        for attribute in [x for x in attrs.keys() if x.endswith('_priv')]:
            if attrs[attribute] is not None:
                val = ['No', 'Yes'][bool(attrs[attribute])]
                elements.append(etree.Element(attribute.upper(), VALUE=val))

        return self._control_tag('USER_INFO', 'MOD_USER', attrib={'USER_LOGIN': user_login}, elements=elements)

    def press_pwr_btn(self):
        """Press the power button"""
        return self._control_tag('SERVER_INFO', 'PRESS_PWR_BTN')

    def profile_apply(self, desc_name, action):
        """Apply a deployment profile"""
        elements = [
            etree.Element('PROFILE_DESC_NAME', attrib={'VALUE': desc_name}),
            etree.Element('PROFILE_OPTIONS', attrib={'VALUE': 'none'}), # Currently unused
            etree.Element('PROFILE_ACTION', attrib={'VALUE': action}),
        ]
        return self._control_tag('RIB_INFO', 'PROFILE_APPLY', elements=elements)

    def profile_apply_get_results(self):
        """Retrieve the results of the last profile_apply"""
        return self._info_tag('RIB_INFO', 'PROFILE_APPLY_GET_RESULTS')

    def profile_delete(self, desc_name):
        """Delet the specified deployment profile"""
        return self._control_tag('RIB_INFO', 'PROFILE_DELETE', elements=[etree.Element('PROFILE_DESC_NAME', attrib={'VALUE': desc_name})])

    def profile_desc_download(self, desc_name, name, description, blob_namespace='perm', blob_name=None, url=None):
        """Make the iLO download a blob and create a deployment profile"""
        elements = [
            etree.Element('PROFILE_DESC_NAME', attrib={'VALUE': desc_name}),
            etree.Element('PROFILE_NAME', attrib={'VALUE': name}),
            etree.Element('PROFILE_DESCRIPTION', attrib={'VALUE': description}),
            etree.Element('PROFILE_SCHEMA', attrib={'VALUE': 'intelligentprovisioning.1.0.0'}),
        ]
        if blob_namespace:
            elements.append(etree.Element('BLOB_NAMESPACE', attrib={'VALUE': blob_namespace}))
        if blob_name:
            elements.append(etree.Element('BLOB_NAME', attrib={'VALUE': blob_name}))
        else:
            elements.append(etree.Element('BLOB_NAME', attrib={'VALUE': desc_name}))
        if url:
            elements.append(etree.Element('PROFILE_URL', attrib={'VALUE': url}))
        return self._control_tag('RIB_INFO', 'PROFILE_DESC_DOWNLOAD', elements=elements)

    def profile_list(self):
        """List all profile descriptors"""
        def process(data):
            if isinstance(data, dict):
                return data.values()
            return data
        return self._info_tag('RIB_INFO', 'PROFILE_LIST', 'PROFILE_DESC_LIST', process=process)

    def hold_pwr_btn(self, toggle=None):
        """Press and hold the power button"""
        attrib = {}
        if toggle is not None:
            attrib['TOGGLE'] = ['No', 'Yes'][bool(toggle)]
        return self._control_tag('SERVER_INFO', 'HOLD_PWR_BTN', attrib=attrib)

    def cold_boot_server(self):
        """Force a cold boot of the server"""
        return self._control_tag('SERVER_INFO', 'COLD_BOOT_SERVER')

    def warm_boot_server(self):
        """Force a warm boot of the server"""
        return self._control_tag('SERVER_INFO', 'WARM_BOOT_SERVER')

    def reset_rib(self):
        """Reset the iLO/RILOE board"""
        return self._control_tag('RIB_INFO', 'RESET_RIB')

    def reset_server(self):
        """Power cycle the server"""
        return self._control_tag('SERVER_INFO', 'RESET_SERVER')

    def send_snmp_test_trap(self):
        """Send an SNMP test trap to the configured alert destinations"""
        return self._control_tag('RIB_INFO', 'SEND_SNMP_TEST_TRAP')

    def set_ahs_status(self, status):
        """Enable or disable AHS logging"""
        status = {True: 'enable', False: 'disable'}[status]
        return self._control_tag('RIB_INFO', 'SET_AHS_STATUS', attrib={'VALUE': status})

    def set_asset_tag(self, asset_tag):
        """Set the server asset tag"""
        return self._control_tag('SERVER_INFO', 'SET_ASSET_TAG', attrib={'VALUE': asset_tag})

    def set_critical_temp_remain_off(self, value):
        """Set whether the server will remain off after a critical temperature shutdown"""
        status = {True: 'Yes', False: 'No'}[value]
        return self._control_tag('SERVER_INFO', 'SET_CRITICAL_TEMP_REMAIN_OFF', attrib={'VALUE': value})

    def set_ers_direct_connect(self, user_id, password, proxy_url=None,
            proxy_port=None, proxy_username=None, proxy_password=None):
        """Register your iLO with HP Insigt Online using Direct Connect. Note
           that you must also call dc_registration_complete"""
        elements = [
            etree.Element('ERS_HPP_USER_ID', attrib={'VALUE': str(user_id)}),
            etree.Element('ERS_HPP_PASSWORD', attrib={'VALUE': str(password)}),
        ]
        for key, value in locals().items():
            if key.startswith('proxy_') and value is not None:
                elements.append(etree.Element('ERS_WEB_' + key, attrib={'VALUE': str(value)}))
        return self._control_tag('RIB_INFO', 'SET_ERS_DIRECT_CONNECT', elements=elements)

    def set_ers_irs_connect(self, ers_destination_url, ers_destination_port):
        """Connect to an Insight Remote Support server"""
        elements = [
            etree.Element('ERS_DESTINATION_URL', attrib={'VALUE': str(ers_destination_url)}),
            etree.Element('ERS_DESTINATION_PORT', attrib={'VALUE': str(ers_destination_port)}),
        ]
        return self._control_tag('RIB_INFO', 'SET_ERS_IRS_CONNECT', elements=elements)

    def set_ers_web_proxy(self, proxy_url, proxy_port, proxy_username=None,
            proxy_password=None):
        """Register your iLO with HP Insigt Online using Direct Connect. Note
           that you must also call dc_registration_complete"""
        elements = []
        for key, value in locals().items():
            if key.startswith('proxy_') and value is not None:
                elements.append(etree.Element('ERS_WEB_' + key, attrib={'VALUE': str(value)}))
        return self._control_tag('RIB_INFO', 'SET_ERS_WEB_PROXY', elements=elements)

    def set_federation_multicast(self, multicast_federation_enabled=True, multicast_discovery_enabled=True,
                                 multicast_announcement_interval=600, ipv6_multicast_scope="Site", multicast_ttl=5):
        """Set the Federation multicast configuration"""
        multicast_federation_enabled = {True: 'Yes', False: 'No'}[multicast_federation_enabled]
        multicast_discovery_enabled = {True: 'Yes', False: 'No'}[multicast_discovery_enabled]
        elements = [
            etree.Element('MULTICAST_FEDERATION_ENABLED', attrib={'VALUE': multicast_federation_enabled}),
            etree.Element('MULTICAST_DISCOVERY_ENABLED', attrib={'VALUE': multicast_discovery_enabled}),
            etree.Element('MULTICAST_ANNOUNCEMENT_INTERVAL', attrib={'VALUE': str(multicast_announcement_interval)}),
            etree.Element('IPV6_MULTICAST_SCOPE', attrib={'VALUE': str(ipv6_multicast_scope)}),
            etree.Element('MULTICAST_TTL', attrib={'VALUE': str(multicast_ttl)}),
        ]
        return self._control_tag('RIB_INFO', 'SET_FEDERATION_MULTICAST', elements=elements)


    def set_language(self, lang_id):
        """Set the default language. Only EN, JA and ZH are supported"""
        return self._control_tag('RIB_INFO', 'SET_LANGUAGE', attrib={'LANG_ID': lang_id})

    def set_host_power(self, host_power=True):
        """Turn host power on or off"""
        power = ['No', 'Yes'][bool(host_power)]
        return self._control_tag('SERVER_INFO', 'SET_HOST_POWER', attrib={'HOST_POWER': power})

    def set_host_power_saver(self, host_power_saver):
        """Set the configuration of the ProLiant power regulator"""
        mapping = {'off': 1, 'min': 2, 'auto': 3, 'max': 4}
        host_power_saver = str(mapping.get(str(host_power_saver).lower(), host_power_saver))
        return self._control_tag('SERVER_INFO', 'SET_HOST_POWER_SAVER', attrib={'HOST_POWER_SAVER': host_power_saver})

    def set_one_time_boot(self, device):
        """Set one time boot device, device should be one of normal, floppy,
           cdrom, hdd, usb, rbsu or network. Ilo 4 also supports EMB-MENU
           (Displays the default boot menu), EMB-ACU (Boots into ACU),
           EMB-HPSUM-AUTO (Boots HPSUM in automatic update mode), EMB-DIAGS
           (Launches Insight Diagnostics for Linux in interactive mode) and
           RBSU (Boots into the system RBSU)"""
        if not device.lower().startswith('boot'):
            device = device.upper()
        return self._control_tag('SERVER_INFO', 'SET_ONE_TIME_BOOT', attrib={'VALUE': device})

    def set_pending_boot_mode(self, boot_mode):
        """Set the boot mode for the next boot to UEFI or legacy"""
        return self._control_tag('SERVER_INFO', 'SET_PENDING_BOOT_MODE', attrib={'VALUE': boot_mode.upper()})

    def set_persistent_boot(self, devices):
        """Set persistent boot order, devices should be comma-separated"""
        elements = []
        if isinstance(devices, basestring):
            devices = devices.split(',')
        for device in devices:
            if not device.lower().startswith('boot'):
                device = device.upper()
            elements.append(etree.Element('DEVICE', VALUE=device))
        return self._control_tag('SERVER_INFO', 'SET_PERSISTENT_BOOT', elements=elements)

    def set_pers_mouse_keyboard_enabled(self, enabled):
        """Enable/disable persistent mouse and keyboard"""
        enabled = {True: 'Yes', False: 'No'}.get(enabled,enabled)
        return self._control_tag('SERVER_INFO', 'SET_PERS_MOUSE_KEYBOARD_ENABLED', attrib={'VALUE': enabled})

    def set_pwreg(self, type, threshold=None, duration=None):
        """Set the power alert threshold"""
        elements = [etree.Element('PWRALERT', TYPE=type)]
        if type.lower() != "disabled":
            elements.append(etree.Element('PWRALERT_SETTINGS', THRESHOLD=str(threshold), DURATION=str(duration)))
        return self._control_tag('SERVER_INFO', 'SET_PWREG', elements=elements)

    def set_power_cap(self, power_cap):
        """Set the power cap feature to a specific value"""
        return self._control_tag('SERVER_INFO', 'SET_POWER_CAP', attrib={'POWER_CAP': str(power_cap)})

    def set_security_msg(self, security_msg, security_msg_text=''):
        """Enables/disables the security message on the iLO login screen and sets its value"""
        enabled = str({True: 'Yes', False: 'No'}.get(security_msg, security_msg))
        text = etree.Element('SECURITY_MSG_TEXT')
        text.append(CDATA(security_msg_text))
        elements = (etree.Element('SECURITY_MSG', VALUE=enabled), text)
        return self._control_tag('RIB_INFO', 'SET_SECURITY_MSG', elements=elements)

    def set_server_auto_pwr(self, setting):
        """Set the automatic power on delay setting. Valid settings are False,
           True (for minumum delay), 15, 30, 45 60 (for that amount of delay)
           or random (for a random delay of up to 60 seconds.)"""
        setting = str({True: 'Yes', False: 'No'}.get(setting, setting))
        return self._control_tag('SERVER_INFO', 'SERVER_AUTO_PWR', attrib={'VALUE': setting})

    def set_server_fqdn(self, fqdn):
        """Set the fqdn of the server"""
        return self._control_tag('SERVER_INFO', 'SERVER_FQDN', attrib={"VALUE": fqdn})

    def set_server_name(self, name):
        """Set the name of the server"""
        try:
            return self._control_tag('SERVER_INFO', 'SERVER_NAME', attrib={"VALUE": name})
        except IloError:
            # In their infinite wisdom, HP decided that only this tag should use value
            # instead of VALUE. And only for certain hardware/firmware combinations.
            # slowclap.mp3
            return self._control_tag('SERVER_INFO', 'SERVER_NAME', attrib={"value": name})

    def set_vf_status(self, boot_option="boot_once", write_protect=True):
        """Set the parameters of the RILOE virtual floppy specified virtual
        media. Valid boot options are boot_once, boot_always, no_boot, connect
        and disconnect."""
        write_protect = ['NO', 'YES'][bool(write_protect)]
        elements = [
            etree.Element('VF_BOOT_OPTION', value=boot_option.upper()),
            etree.Element('VF_WRITE_PROTECT', value=write_protect),
        ]
        return self._control_tag('RIB_INFO', 'SET_VF_STATUS', elements=elements)

    def set_vm_status(self, device="cdrom", boot_option="boot_once", write_protect=True):
        """Set the parameters of the specified virtual media. Valid boot
           options are boot_once, boot_always, no_boot, connect and disconnect.
           Valid devices are floppy and cdrom"""

        write_protect = ['NO', 'YES'][bool(write_protect)]
        elements = [
            etree.Element('VM_BOOT_OPTION', value=boot_option.upper()),
            etree.Element('VM_WRITE_PROTECT', value=write_protect),
        ]
        return self._control_tag('RIB_INFO', 'SET_VM_STATUS', attrib={'DEVICE': device.upper()},
                                 elements=elements)

    def start_dir_test(self, dir_admin_distinguished_name, dir_admin_password, test_user_name, test_user_password):
        """Test directory authentication with the specified credentials"""
        vars = locals()
        del vars['self']
        elements = [etree.Element(x, VALUE=vars[x]) for x in vars]
        return self._control_tag('DIR_INFO', 'START_DIR_TEST', elements=elements)

    def trigger_bb_data(self, message_id, days):
        """Initiate AHS data submission to IRS. The submitted data will include
           the specified message ID and number of days of data"""
        return self._control_tag('RIB_INFO', 'TRIGGER_BB_DATA', attrib={'MESSAGE_ID': message_id, 'BB_DAYS': days})

    def trigger_l2_collection(self, message_id):
        """Initiate an L2 data collection submission to the Insight Remote Support server."""
        element = etree.Element('MESSAGE_ID', attrib={'value': str(message_id)})
        return self._control_tag('RIB_INFO', 'TRIGGER_L2_COLLECTION', elements=[element])

    def trigger_test_event(self, message_id):
        """Trigger a test service event submission to the Insight Remote Support server."""
        element = etree.Element('MESSAGE_ID', attrib={'value': str(message_id)})
        return self._control_tag('RIB_INFO', 'TRIGGER_TEST_EVENT', elements=[element])

    def uid_control(self, uid=False):
        """Turn the UID light on ("Yes") or off ("No")"""
        if isinstance(uid, basestring):
            uid = {'on': True, 'yes': True, 'off': False, 'no': False}.get(uid.lower(), uid)
        uid = ['No', 'Yes'][bool(uid)]
        return self._control_tag('SERVER_INFO', 'UID_CONTROL', attrib={"UID": uid.title()})

    def update_rib_firmware(self, filename=None, version=None, progress=None):
        """Upload new RIB firmware, either specified by filename (.bin or
           .scexe) or version number. Use "latest" as version number to
           download and use the latest available firmware.

           API note:

           As this function may take a while, you can choose to receive
           progress messages by passing a callable in the progress parameter.
           This callable will be called many times to inform you about upload
           and flash progress."""

        if self.delayed:
            raise IloError("Cannot run firmware update in delayed mode")

        if self.read_response:
            raise IloError("Cannot run firmware update in read_response mode")

        if not self.protocol:
            self._detect_protocol()

        # Backwards compatibility
        if filename == 'latest':
            version = 'latest'
            filename = None

        if filename and version:
            raise ValueError("Supply a filename or a version number, not both")

        if not (filename or version):
            raise ValueError("Supply a filename or a version number")

        current_version = self.get_fw_version()
        ilo = current_version['management_processor'].lower()

        if not filename:
            config = hpilo_fw.config(self.firmware_mirror)
            if version == 'latest':
                if ilo not in config:
                    raise IloError("Cannot update %s to the latest version automatically" % ilo)
                version = config[ilo]['version']
            iversion = '%s %s' % (ilo, version)
            if iversion not in config:
                raise ValueError("Unknown firmware version: %s" % version)
            if current_version['firmware_version'] >= version:
                return "Already up-to-date"
            hpilo_fw.download(iversion, progress=progress)
            filename = config[iversion]['file']
        else:
            filename = hpilo_fw.parse(filename, ilo)

        fwlen = os.path.getsize(filename)
        root, inner = self._root_element('RIB_INFO', MODE='write')
        etree.SubElement(inner, 'TPM_ENABLED', VALUE='Yes')
        inner = etree.SubElement(inner, 'UPDATE_RIB_FIRMWARE', IMAGE_LOCATION=filename, IMAGE_LENGTH=str(fwlen))
        if self.protocol == ILO_LOCAL:
            return self._request(root, progress)[1]
        elif self.protocol == ILO_RAW:
            inner.tail = '$EMBED:%s$' % filename
            return self._request(root, progress)[1]
        else:
            self._upload_file(filename, progress)
            return self._request(root, progress)[1]

    def xmldata(self, item='all'):
        """Get basic discovery data which all iLO versions expose over
           unauthenticated https. The default item to query is 'all'. Despite
           its name, it does not return all information. To get license
           information, use 'cpqkey' as argument."""
        if self.delayed:
            raise IloError("xmldata is not compatible with delayed mode")
        if item.lower() not in ('all', 'cpqkey'):
            raise IloError("unsupported xmldata argument '%s', must be 'all' or 'cpqkey'" % item)

        if self.read_response:
            with open(self.read_response) as fd:
                data = fd.read()
        else:
            url = 'https://%s:%s/xmldata?item=%s' % (self.hostname, self.port, item)
            if hasattr(ssl, 'create_default_context'):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                opener = urllib2.build_opener(urllib2.ProxyHandler({}), urllib2.HTTPSHandler(context=ctx))
            else:
                opener = urllib2.build_opener(urllib2.ProxyHandler({}))
            req = opener.open(url, None, self.timeout)
            data = req.read()
            self._debug(1, str(req.headers).rstrip() + "\n\n" + data.decode('ascii', 'iloxml_replace'))
        if self.save_response:
            fd = open(self.save_response, 'a')
            fd.write(data)
            fd.close()
        return self._element_children_to_dict(etree.fromstring(data))

    def _parse_infra2_XXXX(self, element, key, ctag):
        ret = {key: []}
        for elt in element:
            tag = elt.tag.lower()
            if tag == 'bays':
                ret['bays'] = self._element_to_list(elt)
            elif tag == ctag:
                ret[key].append(self._element_children_to_dict(elt))
            else:
                ret[tag] = elt.text
        return {key: ret}

    _parse_infra2_blades = lambda self, element: self._parse_infra2_XXXX(element, 'blades', 'blade')
    _parse_infra2_switches = lambda self, element: self._parse_infra2_XXXX(element, 'switches', 'switch')
    _parse_infra2_managers = lambda self, element: self._parse_infra2_XXXX(element, 'managers', 'manager')
    _parse_infra2_lcds = lambda self, element: self._parse_infra2_XXXX(element, 'lcds', 'lcd')
    _parse_infra2_fans = lambda self, element: self._parse_infra2_XXXX(element, 'fans', 'fan')

    def _parse_infra2_power(self, element):
        ret = self._parse_infra2_XXXX(element, 'power', 'powersupply')
        ret['power']['powersupply'] = ret['power'].pop('power')
        return ret

    def _parse_blade_portmap(self, element):
        ret = {'mezz': []}
        for elt in element:
            if elt.tag.lower() == 'mezz':
                ret['mezz'].append(self._element_children_to_dict(elt))
            elif elt.tag.lower() == 'status':
                ret[elt.tag.lower()] = elt.text.strip()
        return {'portmap': ret}

    def _parse_mezz_slot(self, element):
        ret = {'port': []}
        for elt in element:
            if elt.tag.lower() == 'port':
                ret['port'].append(self._element_children_to_dict(elt))
            elif elt.tag.lower() == 'type':
                ret[elt.tag.lower()] = elt.text.strip()
        return {'slot': ret}

    _parse_portmap_slot = _parse_mezz_slot

    def _parse_mezz_device(self, element):
        ret = {'port': []}
        for elt in element:
            if elt.tag.lower() == 'port':
                ret['port'].append(self._element_children_to_dict(elt))
            else:
                ret[elt.tag.lower()] = elt.text.strip()
        return {'device': ret}

    def _parse_temps_temp(self, element):
        ret = {'thresholds': []}
        for elt in element:
            if elt.tag.lower() == 'threshold':
                ret['thresholds'].append(self._element_children_to_dict(elt))
            else:
                ret[elt.tag.lower()] = elt.text
        return ret

    xmldata_ectd = {
        'hsi': ('virtual',),
        'bladesystem': ('manager',),
        'infra2': ('diag', 'dim', 'vcm', 'vm'),
        'blade': ('bay', 'diag', 'portmap', 'power', 'vmstat'),
        'switch': ('bay', 'diag', 'portmap', 'power'),
        'manager': ('bay', 'diag', 'power'),
        'lcd': ('bay', 'diag'),
        'fan': ('bay',),
        'powersupply': ('bay', 'diag'),
    }
