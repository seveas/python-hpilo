# (c) 2011-2012 Dennis Kaarsemaker <dennis@kaarsemaker.net>
# see COPYING for license details

import os
import random
import re
import socket
import cStringIO as StringIO
import sys
import warnings
try:
    import xml.etree.cElementTree as etree
except ImportError:
    import cElementTree as etree

# Which protocol to use
ILO_RAW  = 1
ILO_HTTP = 2

_untested = []

def untested(meth):
    """Decorator to mark a method as untested"""
    meth.untested = True
    _untested.append(meth.func_name)
    return meth

class IloError(Exception):
    pass

class IloLoginFailed(IloError):
    possible_messages = ['User login name was not found', 'Login failed', 'Login credentials rejected']
    possible_codes = [0x005f, 0x000a]
    pass

class IloWarning(Warning):
    pass

class Ilo(object):
    """Represents an iLO/iLO2/iLO3/RILOE II management interface on a
        specific host. A new connection using the specified login, password
        and timeout will be made for each API call."""

    XML_HEADER = '<?xml version="1.0"?>\r\n'
    HTTP_HEADER = "POST /ribcl HTTP/1.1\r\nHost: localhost\r\nContent-Length: %d\r\nConnection: Close%s\r\n\r\n"
    HTTP_UPLOAD_HEADER = "POST /cgi-bin/uploadRibclFiles HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\nContent-Length: %d\r\nContent-Type: multipart/form-data; boundary=%s\r\n\r\n"
    BLOCK_SIZE = 4096

    def __init__(self, hostname, login, password, timeout=60, port=443):
        self.hostname = hostname
        self.login = login
        self.password = password
        self.timeout  = timeout
        self.debug    = 0
        self.protocol = None
        self.port     = port
        self.cookie   = None

    def __str__(self):
        return "iLO interface of %s" % self.hostname

    def _debug(self, level, message):
        if self.debug >= level:
            if message.startswith('\r'):
                sys.stderr.write(re.sub(r'PASSWORD=".*"','PASSWORD="********"', message))
                sys.stderr.flush()
            else:
                print >>sys.stderr, re.sub(r'PASSWORD=".*"','PASSWORD="********"', message)

    def _request(self, xml, progress=None):
        """Given an ElementTree.Element, serialize it and do the request.
           Returns an ElementTree.Element containing the response"""

        if not self.protocol:
            self._detect_protocol()

        # Serialize the XML
        if hasattr(etree, 'tostringlist'):
            xml = "\r\n".join(etree.tostringlist(xml)) + '\r\n'
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
        # Do a bogus request, using the HTTP protocol. If there is no
        # header (see special case in communicate(), we should be using the
        # raw protocol
        header, data = self._communicate('<RIBCL VERSION="2.0"></RIBCL>', ILO_HTTP)
        if header:
            self.protocol = ILO_HTTP
        else:
            self.protocol = ILO_RAW

    def _upload_file(self, filename, progress):
        firmware = open(filename, 'rb').read()
        boundary = '------hpiLO3t' + str(random.randint(100000,1000000)) + 'z'
        while boundary in firmware:
            boundary = '------hpiLO3t' + str(random.randint(100000,1000000)) + 'z'
        parts = [
            """--%s\r\nContent-Disposition: form-data; name="fileType"\r\n\r\n""" % boundary,
            """\r\n--%s\r\nContent-Disposition: form-data; name="fwimgfile"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n""" % (boundary, filename),
            firmware,
            """\r\n--%s--\r\n""" % boundary
        ]
        total_bytes = sum([len(x) for x in parts])
        sock = self._get_socket()

        self._debug(2, self.HTTP_UPLOAD_HEADER % (total_bytes, boundary))
        sock.write(self.HTTP_UPLOAD_HEADER % (total_bytes, boundary))
        for part in parts:
            if len(part) < 2048:
                self._debug(2, part)
                sock.write(part)
            else:
                sent = 0
                pkglen = 2048
                fwlen = len(part)
                while sent < fwlen:
                    written = sock.write(part[sent:sent+pkglen])
                    sent += written
                    if callable(progress):
                        progress("\r\033[KSent %d/%d bytes (%d%%)" % (sent, fwlen, 100.0*sent/fwlen))
                    else:
                        self._debug(2, "\r\033[KSent %d/%d bytes (%d%%)" % (sent, fwlen, 100.0*sent/fwlen))
                if callable(progress):
                    progress("")
                else:
                    self._debug(2, "")


        data = ''
        try:
            while True:
                d = sock.read()
                data += d
                if not d:
                    break
        except socket.sslerror, e: # Connection closed
            if not data:
                raise IloError("Communication with %s:%d failed: %s" % (self.hostname, self.port, str(e)))

        self._debug(1, "Received %d bytes" % len(data))
        self._debug(2, data)
        self.cookie = re.search('Set-Cookie: *(.*)', data).groups(1)
        self._debug(2, "Cookie: %s" % self.cookie)

    def _get_socket(self):
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
            return socket.ssl(sock)
        except socket.sslerror, e:
            raise IloError("Cannot establish ssl session with %s:%d: %s" % (self.hostname, self.port, e.message))

    def _communicate(self, xml, protocol, progress=None):
        sock = self._get_socket()
        msglen = msglen_ = len(self.XML_HEADER + xml)
        if protocol == ILO_HTTP:
            extra_header = ''
            if self.cookie:
                extra_header = "\r\nCookie: %s" % self.cookie
            http_header = self.HTTP_HEADER % (msglen, extra_header)
            msglen += len(http_header)
        self._debug(1, "Sending XML request, %d bytes" % msglen)

        if protocol == ILO_HTTP:
            self._debug(2, http_header)
            sock.write(http_header)

        self._debug(2, self.XML_HEADER + xml)

        # XML header and data need to arrive in 2 distinct packets
        sock.write(self.XML_HEADER)
        if '$EMBED' in xml:
            pre, name, post = re.compile(r'(.*)\$EMBED:(.*)\$(.*)', re.DOTALL).match(xml).groups()
            sock.write(pre)
            sent = 0
            fwlen = os.path.getsize(name)
            fw = open(name, 'rb').read()
            pkglen = 2048
            while sent < fwlen:
                written = sock.write(fw[sent:sent+pkglen])
                sent += written
                if callable(progress):
                    progress("\r\033[KSent %d/%d bytes (%d%%)" % (sent, fwlen, 100.0*sent/fwlen))
                else:
                    self._debug(2, "\r\033[KSent %d/%d bytes (%d%%)" % (sent, fwlen, 100.0*sent/fwlen))
            if callable(progress):
                progress("")
            else:
                self._debug(2, "")
            sock.write(post.strip())
        else:
            sock.write(xml)

        # And grab the data
        data = ''
        try:
            while True:
                d = sock.read()
                data += d
                if not d:
                    break
                if callable(progress) and d.strip().endswith('</RIBCL>'):
                    d = d[d.find('<?xml'):]
                    while '<?xml' in d:
                        end = d.find('<?xml', 5)
                        if end == -1:
                            progress(self._parse_message(d, include_inform=True))
                            break
                        else:
                            progress(self._parse_message(d[:end], include_inform=True))
                            d = d[end:]
        except socket.sslerror, e: # Connection closed
            if not data:
                raise IloError("Communication with %s:%d failed: %s" % (self.hostname, self.port, str(e)))

        self._debug(1, "Received %d bytes" % len(data))

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
        else:
            header = None

        self._debug(2, "%s\r\n\r\n%s" % (header_, data))
        return header, data


    def _root_element(self, element, **attrs):
        """Create a basic XML structure for a message. Return root and innermost element"""
        root = etree.Element('RIBCL', VERSION="2.0")
        login = etree.SubElement(root, 'LOGIN', USER_LOGIN=self.login, PASSWORD=self.password)
        element = etree.SubElement(login, element, **attrs)
        return root, element

    def _parse_message(self, data, include_inform=False):
        """Parse iLO responses into Element instances and remove useless messages"""
        # Bug in some ilo versions causes malformed XML
        if '<RIBCL VERSION="2.22"/>' in data:
            data = data.replace('<RIBCL VERSION="2.22"/>', '<RIBCL VERSION="2.22">')
        if re.search(r'''= *[^"']''', data):
            data = re.sub(r'''= *([^"'\n]+?) *\n''', r'="\1"', data)
        data = data.strip()
        if not data:
            return None

        message = etree.fromstring(data)
        if message.tag == 'RIBCL':
            for child in message:
                if child.tag == 'INFORM':
                    if include_inform:
                        # Filter useless message:
                        if 'should be updated' in child.text:
                            return None
                        return child.text
                # RESPONE with status 0 also adds no value
                elif child.tag == 'RESPONSE' and int(child.get('STATUS'), 16) == 0:
                    if child.get('MESSAGE') != 'No error':
                        warnings.warn(child.get('MESSAGE'), IloWarning)
                # These are interesting, something went wrong
                elif child.tag == 'RESPONSE':
                    if 'syntax error' in child.get('MESSAGE') and not self.protocol:
                        # This is triggered when doing protocol detection, ignore
                        pass
                    else:
                        if int(child.get('STATUS'), 16) in IloLoginFailed.possible_codes or \
                                child.get('MESSAGE') in IloLoginFailed.possible_messages:
                            raise IloLoginFailed
                        raise IloError("Error communicating with iLO: %s" % child.get('MESSAGE'))
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
            key, val, unit = elt.tag.lower(), elt.get('VALUE', elt.get('value', None)), elt.get('UNIT', None)
            if val is None:
                # HP is not best friends with consistency. Sometimes there are
                # attributes, sometimes child tags and sometimes text nodes. Oh
                # well, deal with it :)
                if list(elt):
                    val = self._element_to_dict(elt)
                elif elt.text:
                    val = elt.text
                elif elt.attrib:
                    val = self._element_to_dict(elt)

            val = self._coerce(val)

            if unit:
                if isinstance(retval, list):
                    retval.append((val,unit))
                else:
                    retval[key] = (val, unit)
            else:
                if isinstance(retval, list):
                    retval.append(val)
                else:
                    retval[key] = val
        return retval

    def _element_to_dict(self, element):
        """Returns a dict with tag attributes as items"""
        retval = {}
        for key, val in element.attrib.iteritems():
            retval[key.lower()] = self._coerce(val)
        return retval

    def _coerce(self, val):
        """Do some data type coercion: unquote, turn integers into integers and
           Y/N into booleans"""
        if isinstance(val, basestring):
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            if val.isdigit():
                val = int(val)
            else:
                val = {'Y': True, 'N': False}.get(val, val)
        return val

    def _raw(self, *tags):
        root, inner = self._root_element(tags[0][0], **(tags[0][1]))
        for t in tags[1:]:
            inner = etree.SubElement(inner, t[0], **t[1])
        header, message = self._request(root)
        fd = StringIO.StringIO()
        etree.ElementTree(message).write(fd)
        ret = fd.getvalue()
        fd.close()
        return ret

    def _info_tag(self, infotype, tagname, returntag=None, attrib={}):
        root, inner = self._root_element(infotype, MODE='read')
        etree.SubElement(inner, tagname, **attrib)
        header, message = self._request(root)
        message = message.find(returntag or tagname)
        if list(message):
            return self._element_children_to_dict(message)
        else:
            return self._element_to_dict(message)

    def _info_tag2(self, infotype, tagname, returntag=None, key=None):
        root, inner = self._root_element(infotype, MODE='read')
        etree.SubElement(inner, tagname)
        header, message = self._request(root)
        message = message.find(returntag or tagname)

        if key:
            retval = {}
        else:
            retval = []
        for elt in message:
            elt = self._element_to_dict(elt)
            if key:
                retval[elt[key]] = elt
            else:
                retval.append(elt)
        return retval

    def _control_tag(self, controltype, tagname, returntag=None, attrib={}, elements=[], text=None):
        root, inner = self._root_element(controltype, MODE='write')
        inner = etree.SubElement(inner, tagname, **attrib)
        if text:
            inner.text = text
        for element in elements:
            inner.append(element)
        header, message = self._request(root)
        if message is None:
            return None
        message = message.find(returntag or tagname)
        if message.text.strip():
            return message.text.strip()
        raise IloError("You've reached unknown territories, please report a bug")
        if list(message):
            return self._element_children_to_dict(message)
        else:
            return self._element_to_dict(message)

    def activate_license(self, key):
        """Activate an iLO advanced license"""
        license = etree.Element('ACTIVATE', KEY=key)
        return self._control_tag('RIB_INFO', 'LICENSE', elements=[license])

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
                attrib={'USER_LOGIN': user_login, 'USER_NAME': user_name, 'PASSWORD': password})

    def cert_fqdn(self, use_fqdn):
        """Configure whether to use the fqdn or the short hostname for certificate requests"""
        use_fqdn = str({True: 'Yes', False: 'No'}.get(use_fqdn, use_fqdn))
        return self._control_tag('RIB_INFO', 'CERT_FQDN', attrib={'VALUE': use_fqdn})

    def certificate_signing_request(self):
        """Get a certificate signing request from the iLO"""
        return self._control_tag('RIB_INFO', 'CERTIFICATE_SIGNING_REQUEST')

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
            raise IloError("A value must be specified for computer_lock")
        elements = [etree.Element('COMPUTER_LOCK', VALUE=computer_lock)]
        if computer_lock_key:
            elements.append(etree.Element('COMPUTER_LOCK_KEY', VALUE=computer_lock_key))
        return self._control_tag('RIB_INFO', 'COMPUTER_LOCK_CONFIG', elements=elements)

    def delete_user(self, user_login):
        """Delete the specified user from the ilo"""
        return self._control_tag('USER_INFO', 'DELETE_USER', attrib={'USER_LOGIN': user_login})

    def eject_virtual_floppy(self):
        """Eject the virtual floppy"""
        return self._control_tag('RIB_INFO', 'EJECT_VIRTUAL_FLOPPY')

    def eject_virtual_media(self, device="cdrom"):
        """Eject the virtual media attached to the specified device"""
        return self._control_tag('RIB_INFO', 'EJECT_VIRTUAL_MEDIA', attrib={"DEVICE": device.upper()})

    def factory_defaults(self):
        """Reset the iLO to factory default settings"""
        return self._control_tag('RIB_INFO', 'FACTORY_DEFAULTS')

    def get_all_users(self):
        """Get a list of all loginnames"""
        data = self._info_tag2('USER_INFO', 'GET_ALL_USERS', key='value')
        return [x for x in data if x]

    def get_all_user_info(self):
        """Get basic and authorization info of all users"""
        return self._info_tag2('USER_INFO', 'GET_ALL_USER_INFO', key='user_login')

    def get_cert_subject_info(self):
        """Get ssl certificate subject information"""
        return self._info_tag('RIB_INFO', 'GET_CERT_SUBJECT_INFO', 'CSR_CERT_SETTINGS')

    def get_dir_config(self):
        """Get directory authentication configuration"""
        return self._info_tag('DIR_INFO', 'GET_DIR_CONFIG')

    def get_embedded_health(self):
        """Get server health information"""
        root, attach = self._root_element('SERVER_INFO', MODE='read')
        etree.SubElement(attach, 'GET_EMBEDDED_HEALTH')

        header, message = self._request(root)

        health = {}
        for category in message.find('GET_EMBEDDED_HEALTH_DATA'):
            tag = category.tag.lower()
            if not list(category):
                health[tag] = None
            elif not list(category[0]):
                health[tag] = {}
                for elt in category:
                    elttag = elt.tag.lower()
                    if elttag not in health[tag]:
                        health[tag][elttag] = {}
                    health[tag][elttag].update(self._element_to_dict(elt))
            else:
                health[tag] = [self._element_children_to_dict(x) for x in category]
                if 'location' in health[tag][0]:
                    health[tag] = dict((x['location'], x) for x in health[tag])
                elif 'label' in health[tag][0]:
                    health[tag] = dict((x['label'], x) for x in health[tag])
        return health

    def get_fw_version(self):
        """Get the iLO firmware version"""
        return self._info_tag('RIB_INFO', 'GET_FW_VERSION')

    def get_global_settings(self):
        """Get global iLO settings"""
        return self._info_tag('RIB_INFO', 'GET_GLOBAL_SETTINGS')

    def get_host_data(self, decoded_only=True):
        """Get SMBIOS records that describe the host. By default only the ones
           where human readable information is available are returned. To get
           all records pass :attr:`decoded_only=False` """

        root, attach = self._root_element('SERVER_INFO', MODE='read')
        etree.SubElement(attach, 'GET_HOST_DATA')

        header, message = self._request(root)

        records = []
        for record in message.find('GET_HOST_DATA').findall('SMBIOS_RECORD'):
            if decoded_only and not list(record):
                continue
            record_ = self._element_to_dict(record)
            record_['fields'] = []
            for field in list(record):
                record_['fields'].append(self._element_to_dict(field))
            names = [x['name'] for x in record_['fields']]
            if len(names) == len(set(names)):
                for field in record_['fields']:
                    record_[field['name']] = field['value']
                del record_['fields']
            records.append(record_)
        return records

    def get_host_power_saver_status(self):
        """Get the configuration of the ProLiant power regulator"""
        return self._info_tag('SERVER_INFO', 'GET_HOST_POWER_SAVER_STATUS', 'GET_HOST_POWER_SAVER')

    def get_host_power_status(self):
        """Whether the server is powered on or not"""
        data = self._info_tag('SERVER_INFO', 'GET_HOST_POWER_STATUS', 'GET_HOST_POWER')
        return data['host_power']

    def get_host_pwr_micro_ver(self):
        """Get the version of the power micro firmware"""
        data = self._info_tag('SERVER_INFO', 'GET_HOST_PWR_MICRO_VER')
        return data['pwr_micro']['version']

    def get_ilo_event_log(self):
        """Get the full iLO event log"""
        return self._info_tag2('RIB_INFO', 'GET_EVENT_LOG', 'EVENT_LOG')

    def get_language(self):
        """Get the default language set"""
        return self._info_tag('RIB_INFO', 'GET_LANGUAGE')

    def get_all_languages(self):
        """Get the list of installed languages - broken because iLO returns invalid XML"""
        return self._info_tag('RIB_INFO', 'GET_ALL_LANGUAGES')

    def get_network_settings(self):
        """Get the iLO network settings"""
        return self._info_tag('RIB_INFO', 'GET_NETWORK_SETTINGS')

    def get_oa_info(self):
        """Get information about the OA of the enclosing chassis"""
        return self._info_tag('BLADESYSTEM_INFO', 'GET_OA_INFO')

    def get_one_time_boot(self):
        """Get the one time boot state of the host"""
        return self._info_tag('SERVER_INFO', 'GET_ONE_TIME_BOOT', 'ONE_TIME_BOOT')

    def get_persistent_boot(self):
        """Get the boot order of the host"""
        return self._info_tag('SERVER_INFO', 'GET_PERSISTENT_BOOT', 'PERSISTENT_BOOT')

    def get_power_cap(self):
        """Get the power cap setting"""
        data = self._info_tag('SERVER_INFO', 'GET_POWER_CAP')
        return data['power_cap']

    def get_power_readings(self):
        """Get current, min, max and average power readings"""
        return self._info_tag('SERVER_INFO', 'GET_POWER_READINGS')

    def get_pwreg(self):
        """Get the power and power alert threshold settings"""
        return self._info_tag('SERVER_INFO', 'GET_PWREG')

    def get_server_auto_pwr(self):
        """Get the automatic power on delay setting"""
        data = self._info_tag('SERVER_INFO', 'GET_SERVER_AUTO_PWR')
        return data['server_auto_pwr']

    def get_server_event_log(self):
        """Get the IML log of the server"""
        return self._info_tag2('SERVER_INFO', 'GET_EVENT_LOG', 'EVENT_LOG')

    def get_server_name(self):
        """Get the name of the server this iLO is managing"""
        name = self._info_tag('SERVER_INFO', 'GET_SERVER_NAME', 'SERVER_NAME')
        return name['value']

    def get_server_power_on_time(self):
        """How many minutes ago has the server been powered on"""
        minutes = self._info_tag('SERVER_INFO', 'GET_SERVER_POWER_ON_TIME', 'SERVER_POWER_ON_MINUTES')
        return int(minutes['value'])

    def get_snmp_im_settings(self):
        """Where does the iLO send SNMP traps to and which traps does it send"""
        return self._info_tag('RIB_INFO', 'GET_SNMP_IM_SETTINGS')

    def get_sso_settings(self):
        """Get the HP SIM Single Sign-On settings"""
        root, attach = self._root_element('SSO_INFO', MODE='read')
        etree.SubElement(attach, 'GET_SSO_SETTINGS')

        header, message = self._request(root)

        retval = {}
        for record in message.find('GET_SSO_SETTINGS'):
            tag = record.tag.lower()
            attrib = record.attrib
            if 'VALUE' in attrib:
                retval[tag] = self._coerce(attrib['VALUE'])
                continue
            if tag not in retval:
                retval[tag] = {}
            retval[tag].update(dict([(x[0].lower(), self._coerce(x[1])) for x in attrib.items()]))
        return retval

    def get_twofactor_settings(self):
        """Get two-factor authentication settings"""
        return self._info_tag('RIB_INFO', 'GET_TWOFACTOR_SETTINGS')

    def get_uid_status(self):
        """Get the status of the UID light"""
        data = self._info_tag('SERVER_INFO', 'GET_UID_STATUS')
        return data['uid']

    def get_user(self, user_login):
        """Get user info about a specific user"""
        return self._info_tag('USER_INFO', 'GET_USER', attrib={'USER_LOGIN': user_login})

    def get_vm_status(self, device="CDROM"):
        """Get the status of virtual media devices. Valid devices are FLOPPY and CDROM"""
        return self._info_tag('RIB_INFO', 'GET_VM_STATUS', attrib={'DEVICE': device})

    def hotkey_config(self, ctrl_t=None, ctrl_u=None, ctrl_v=None, ctrl_w=None,
                      ctrl_x=None, ctrl_y=None):
        """Change a set of shortcuts"""
        vars = locals()
        del vars['self']
        elements = [etree.Element(x.upper(), VALUE=vars[x]) for x in vars if vars[x] is not None]
        return self._control_tag('RIB_INFO', 'HOTKEY_CONFIG', elements=elements)

    def import_certificate(self, certificate):
        """Import a signed SSL certificate"""
        return self._control_tag('RIB_INFO', 'IMPORT_CERTIFICATE', text=certificate)

    @untested
    def import_ssh_key(self, user_login, ssh_key):
        """Imports an SSH key for the specified user. The value of ssh_key
           should be the content of an id_dsa.pub file"""
        # Basic sanity checking
        if ' ' not in ssh_key:
            raise ValueError("Invalid SSH key")
        algo, key = ssh_key.split(' ',2)[:2]
        if algo not in ('ssh-dss', 'ssh-rsa'):
            raise ValueError("Invalid SSH key")
        try:
            key.decode('base64')
        except Exception:
            raise ValueError("Invalid SSH key")
        key = "-----BEGIN SSH KEY-----\r\n%s %s %s\r\n----END SSH KEY-----" % (algo, key, user_login)
        return self._control_tag('RIB_INFO', 'IMPORT_SSH_KEY', text=key)

    # Not sure how this would work, and I have no relevant hardware
    #def insert_virtual_floppy(self, device, image_location):
    #    """Insert a virtual floppy"""
    #    return self._control_tag('RIB_INFO', 'INSERT_VIRTUAL_FLOPPY', attrib={'IMAGE_LOCATION': image_location})

    @untested
    def delete_ssh_key(self, user_login):
        """Delete a users SSH key"""
        return self._control_tag('USER_INFO', 'MOD_USER', elements=[etree.Element('DEL_USERS_SSH_KEY')])

    def insert_virtual_media(self, device, image_url):
        """Insert a virtual floppy or CDROM. Note that you will also need to
           use :func:`set_vm_status` to connect the media"""
        return self._control_tag('RIB_INFO', 'INSERT_VIRTUAL_MEDIA', attrib={'DEVICE': device.upper(), 'IMAGE_URL': image_url})

    def mod_global_settings(self, session_timeout=None, f8_prompt_enabled=None,
            f8_login_required=None, lock_configuration=None,
            http_port=None, https_port=None, ssh_port=None, ssh_status=None,
            vmedia_disable=None, virtual_media_port=None, remote_console_port=None,
            min_password=None, enfoce_aes=None, authentication_failure_logging=None,
            rbsu_post_ip=None, remote_console_encryption=None, remote_keyboard_model=None,
            terminal_services_port=None, high_performance_mouse=None,
            shared_console_enable=None, shared_console_port=None,
            remote_console_acquire=None):
        """Modify iLO global settings, only values that are specified will be changed."""
        vars = dict(locals())
        del vars['self']
        elements = [etree.Element(x.upper(), VALUE=str({True: 'Yes', False: 'No'}.get(vars[x], vars[x])))
                    for x in vars if vars[x] is not None]
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
            shared_network_port_vlan=None, shared_network_port_vlan_id=None):
        """Configure the network settings for the iLO card"""
        vars = dict(locals())
        del vars['self']
        elements = [etree.Element(x.upper(), VALUE=str({True: 'Yes', False: 'No'}.get(vars[x], vars[x])))
                    for x in vars if vars[x] is not None]
        return self._control_tag('RIB_INFO', 'MOD_NETWORK_SETTINGS', elements=elements)

    def mod_snmp_im_settings(self, web_agent_ip_address=None, snmp_address_1=None,
            snmp_address_2=None, snmp_address_3=None, os_traps=None,
            snmp_passthrough_status=None, rib_traps=None, cim_security_mask=None):
        """Configure the SNMP and Insight Manager integration settings"""
        vars = dict(locals())
        del vars['self']
        elements = [etree.Element(x.upper(), VALUE=str({True: 'Yes', False: 'No'}.get(vars[x], vars[x])))
                    for x in vars if vars[x] is not None]
        return self._control_tag('RIB_INFO', 'MOD_SNMP_IM_SETTINGS', elements=elements)

    def mod_user(self, user_login, user_name=None, password=None,
            admin_priv=None, remote_cons_priv=None, reset_server_priv=None,
            virtual_media_priv=None, config_ilo_priv=None):
        """Set attributes for a user, only specified arguments will be changed.
           All arguments except user_name and password should be boolean"""

        attrs = locals()
        elements = []
        for attribute in ('user_name', 'password'):
            if attrs[attribute] is not None:
                elements.append(etree.Element(attribute.upper(), VALUE=attrs[attribute]))
        for attribute in [x for x in attrs.keys() if x.endswith('_priv')]:
            if attrs[attribute] is not None:
                val = ['No', 'Yes'][bool(attrs[attribute])]
                elements.append(etree.Element(attribute.upper(), VALUE=val))

        return self._control_tag('USER_INFO', 'MOD_USER', attrib={'USER_LOGIN': user_login}, elements=elements)

    def press_pwr_btn(self):
        """Press the power button"""
        return self._control_tag('SERVER_INFO', 'PRESS_PWR_BTN')

    def hold_pwr_btn(self):
        """Press and hold the power button"""
        return self._control_tag('SERVER_INFO', 'HOLD_PWR_BTN')

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

    def set_language(self, lang_id):
        """Set the default language"""
        return self._control_tag('RIB_INFO', 'SET_LANGUAGE', attrib={'LANG_ID': lang_id})

    def set_host_power(self, host_power=True):
        """Turn host power on or off"""
        power = ['No', 'Yes'][bool(host_power)]
        return self._control_tag('SERVER_INFO', 'SET_HOST_POWER', attrib={'HOST_POWER': power})

    def set_host_power_saver(self, host_power_saver):
        """Set the configuration of the ProLiant power regulator"""
        return self._control_tag('SERVER_INFO', 'SET_HOST_POWER_SAVER', attrib={'HOST_POWER_SAVER': str(host_power_saver)})

    def set_one_time_boot(self, device):
        """Set one time boot device"""
        return self._control_tag('SERVER_INFO', 'SET_ONE_TIME_BOOT', attrib={'VALUE': device.upper()})

    def set_persistent_boot(self, devices):
        """Set persistent boot order, devices should be comma-separated"""
        elements = [etree.Element('DEVICE', VALUE=x.upper()) for x in devices.split(',')]
        return self._control_tag('SERVER_INFO', 'SET_PERSISTENT_BOOT', elements=elements)

    def set_pwreg(self, type, threshold=None, duration=None):
        """Set the power alert threshold"""
        elements = [etree.Element('PWRALERT', TYPE=type)]
        if type.lower() != "disabled":
            elements.append(etree.Element('PWRALERT_SETTINGS', THRESHOLD=str(threshold), DURATION=str(duration)))
        return self._control_tag('SERVER_INFO', 'SET_PWREG', elements=elements)

    def set_power_cap(self, power_cap):
        """Set the power cap feature to a specific value"""
        return self._control_tag('SERVER_INFO', 'SET_POWER_CAP', attrib={'POWER_CAP': str(power_cap)})

    def set_server_auto_pwr(self, setting):
        """Set the automatic power on delay setting. Valid settings are False,
           True (for minumum delay), 15, 30, 45 60 (for that amount of delay or
           random (for a random delay of up to 60 seconds.)"""
        setting = str({True: 'Yes', False: 'No'}.get(setting, setting))
        return self._control_tag('SERVER_INFO', 'SERVER_AUTO_PWR', attrib={'VALUE': setting})

    def set_server_name(self, name):
        """Set the name of the server"""
        return self._control_tag('SERVER_INFO', 'SERVER_NAME', attrib={"VALUE": name})

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

    def uid_control(self, uid="No"):
        """Turn the UID light on ("Yes") or off ("No")"""
        if uid.lower() not in ('yes', 'no'):
            raise ValueError("uid should be Yes or No")
        return self._control_tag('SERVER_INFO', 'UID_CONTROL', attrib={"UID": uid.title()})

    def update_rib_firmware(self, filename, progress=None):
        """Upload new RIB firmware"""
        if not self.protocol:
            self._detect_protocol()

        if progress:
            def progress_(data):
                if data is None:
                    return
                elif isinstance(data, basestring):
                    if '%' in data:
                        data = '\r\033[K' + data
                    progress(data)
                else:
                    raise RuntimeError("Unknown progress message")
        else:
            progress_ = None

        fwlen = os.path.getsize(filename)
        root, inner = self._root_element('RIB_INFO', MODE='write')
        etree.SubElement(inner, 'TPM_ENABLED', VALUE='Yes')
        inner = etree.SubElement(inner, 'UPDATE_RIB_FIRMWARE', IMAGE_LOCATION=filename, IMAGE_LENGTH=str(fwlen))
        if self.protocol == ILO_RAW:
            inner.tail = '$EMBED:%s$' % filename
            return self._request(root, progress_)[1]
        else:
            self._upload_file(filename, progress_)
            return self._request(root, progress_)[1]


##############################################################################################
#### All functions below require hardware I don't have access to

    @untested
    def get_all_cables_status(self):
        """FIXME: I have no relevant hardware. Please report sample output"""
        return self._raw(('SERVER_INFO', {'MODE': 'READ'}), ('GET_ALL_CABLES_STATUS', {}))

    @untested
    def get_diagport(self):
        """FIXME: I have no relevant hardware. Please report sample output"""
        return self._raw(('RACK_INFO', {'MODE': 'READ'}), ('GET_DIAGPORT_SETTINGS', {}))

    @untested
    def get_enclosure_ip_settings(self):
        """FIXME: I have no relevant hardware. Please report sample output"""
        return self._raw(('RACK_INFO', {'MODE': 'READ'}), ('GET_ENCLOSURE_IP_SETTINGS', {}))

    @untested
    def get_host_power_reg_info(self):
        """FIXME: I have no relevant hardware. Please report sample output"""
        return self._raw(('SERVER_INFO', {'MODE': 'READ'}), ('GET_HOST_POWER_REG_INFO', {}))

    @untested
    def get_topology(self):
        """FIXME: I have no relevant hardware. Please report sample output"""
        return self._raw(('SERVER_INFO', {'MODE': 'READ'}), ('GET_TOPOLOGY', {}))

    @untested
    def get_vpb_capable_status(self):
        """FIXME: I have no relevant hardware. Please report sample output"""
        return self._raw(('SERVER_INFO', {'MODE': 'READ'}), ('GET_VPB_CAPABLE_STATUS', {}))

    @untested
    def get_vf_status(self):
        """FIXME: I have no relevant hardware. Please report sample output"""
        return self._info_tag('RIB_INFO', 'GET_VF_STATUS')

