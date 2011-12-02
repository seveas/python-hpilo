# (c) 2011 Dennis Kaarsemaker <dennis@kaarsemaker.net>
# see COPYING for license details

import socket
import cStringIO as StringIO
import sys
import xml.etree.cElementTree as etree

# Which protocol to use
ILO_RAW  = 1
ILO_HTTP = 2

class IloError(Exception):
    pass

class Ilo(object):
    XML_HEADER = '<?xml version="1.0"?>\r\n'
    HTTP_HEADER = "POST /ribcl HTTP/1.1\r\nHost: localhost\r\nContent-length: %d\r\nConnection: Close\r\n\r\n"

    def __init__(self, hostname, login, password, timeout=60):
        self.hostname = hostname
        self.login = login
        self.password = password
        self.timeout  = timeout
        self.debug    = 0
        self.protocol = None
        self.port     = 443

    def __str__(self):
        return "iLO interface of %s" % self.hostname

    def _debug(self, level, message):
        if self.debug >= level:
            print >>sys.stderr, message
 
    def _request(self, xml):
        """Given an ElementTree.Element, serialize it and do the request.
           Returns an ElementTree.Element containing the response"""

        if not self.protocol:
            # Do a bogus request, using the HTTP protocol. If there is no
            # header (see special case in communicate(), we should be using the
            # raw protocol
            header, data = self._communicate('<RIBCL VERSION="2.0"></RIBCL>', ILO_HTTP)
            if header:
                self.protocol = ILO_HTTP
            else:
                self.protocol = ILO_RAW

        # Serialize the XML
        xml = "\r\n".join(etree.tostringlist(xml)) + '\r\n'

        header, data =  self._communicate(xml, self.protocol)

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

        if len(messages) == 1:
            return header, messages[0]

        return header, messages
    
    def _communicate(self, xml, protocol):
        """Set up an https connection and do an HTTP/raw socket request"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        self._debug(1, "Connecting to %s:%d" % (self.hostname, self.port))
        try:
            sock.connect((self.hostname, self.port))
        except socket.timeout:
            raise IloError("Timeout connecting to %s:%d" % (self.hostname, self.port))
        except socket.error, e:
            raise IloError("Error connecting to %s:%d: %s" % (self.hostname, self.port, str(e)))
        try:
            sock = socket.ssl(sock)
        except socket.sslerror, e:
            raise IloError("Cannot establish ssl session with %s:%d: %s" % (self.hostname, self.port, e.message))

        msglen = msglen_ = len(self.XML_HEADER + xml)
        if protocol == ILO_HTTP:
            http_header = self.HTTP_HEADER % msglen
            msglen += len(http_header)
        self._debug(1, "Sending XML request, %d bytes" % msglen)

        if protocol == ILO_HTTP:
            self._debug(2, http_header)
            sock.write(http_header)

        self._debug(2, self.XML_HEADER + xml)
 
        # XML header and data need to arrive in 2 distinct packets
        sock.write(self.XML_HEADER)
        sock.write(xml)

        # And grab the data
        data = ''
        try:
            while True:
                d = sock.read()
                data += d
                if not d:
                    break
        except socket.sslerror: # Connection closed
            if not data:
                raise IloError("Communication with %s:%d failed: %s" % (self.hostname, self.port, str(e)))

        self._debug(1, "Received %d bytes" % len(data))
        self._debug(2, data)

        # Do we have HTTP?
        if protocol == ILO_HTTP and data.startswith('HTTP/1.1 200'):
            header, data = data.split('\r\n\r\n', 1)
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
            data = ''
        else:
            header = None
        return header, data


    def _root_element(self, element, **attrs):
        """Create a basic XML structure for a message. Return root and innermost element"""
        root = etree.Element('RIBCL', VERSION="2.0")
        login = etree.SubElement(root, 'LOGIN', USER_LOGIN=self.login, PASSWORD=self.password)
        element = etree.SubElement(login, element, **attrs)
        return root, element
    
    def _parse_message(self, data):
        """Parse iLO responses into Element instances and remove useless messages"""
        # Bug in some ilo versions causes malformed XML
        if '<RIBCL VERSION="2.22"/>' in data:
            data = data.replace('<RIBCL VERSION="2.22"/>', '<RIBCL VERSION="2.22">')
        data = data.strip()
        if not data:
            return None

        message = etree.fromstring(data)
        if message.tag == 'RIBCL':
            for child in message:
                # INFORM messages are useless
                if child.tag == 'INFORM':
                    pass
                # RESPONE with status 0 also adds no value
                elif child.tag == 'RESPONSE' and int(child.get('STATUS'), 16) == 0:
                    pass
                # These are interesting, something went wrong
                elif child.tag == 'RESPONSE':
                    if 'syntax error' in child.get('MESSAGE') and not self.protocol:
                        # This is triggered when doing protocol detection, ignore
                        pass
                    else:
                        raise IloError("Error communicating with iLO: %s" % child.get('MESSAGE'))
                # And this type of message is the actual payload.
                else:
                    return message
            return None
        # This shouldn't be reached as all messages are RIBCL messages. But who knows!
        return message

    def _element_children_to_dict(self, element):
        """Returns a dict with tag names of all child elements as keys and the
           VALUE attributes as values. Also does some type normalization."""
        retval = {}
        for elt in element:
            key, val = elt.tag.lower(), elt.get('VALUE', None)
            if val and val.isdigit():
                val = int(val)
            else:
                val = {'Y': True, 'N': False}.get(val, val)
            retval[key] = val
        return retval

    def _element_to_dict(self, element):
        """Returns a dict with tag attributes as items. Also does some type normalization."""
        retval = {}
        for key, val in element.attrib.iteritems():
            retval[key.lower()] = {'Y': True, 'N': False}.get(val, val)
        return retval

    def _info_tag(self, infotype, tagname):
        root, inner = self._root_element(infotype, MODE='read')
        etree.SubElement(inner, tagname)
        header, message = self._request(root)
        return self._element_children_to_dict(message.find(tagname))


    def get_global_settings(self):
        """Get global iLO settings"""
        return self._info_tag('RIB_INFO', 'GET_GLOBAL_SETTINGS')

    def get_twofactor_settings(self):
        """Get two-factor authentication settings"""
        return self._info_tag('RIB_INFO', 'GET_TWOFACTOR_SETTINGS')

    # Doesn't work
    #def get_all_cables_status(self):
    #    return self._info_tag('SERVER_INFO', 'GET_ALL_CABLES_STATUS')

    def get_all_user_info(self):
        """Get basic and authorization info of all users"""
        root, attach = self._root_element('USER_INFO', MODE='read')
        etree.SubElement(attach, 'GET_ALL_USER_INFO')

        header, message = self._request(root)
        users = {}
        for user in message.find('GET_ALL_USER_INFO'):
            user = self._element_to_dict(user)
            users[user['user_login']] = user
        return users

    def get_all_users(self):
        """Get a list of all loginnames"""
        root, attach = self._root_element('USER_INFO', MODE='read')
        etree.SubElement(attach, 'GET_ALL_USERS')

        header, message = self._request(root)
        users = {}
        return [x.get('VALUE') for x in message.find('GET_ALL_USERS').findall('USER_LOGIN') if x.get('VALUE')]
