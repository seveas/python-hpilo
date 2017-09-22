Access from Python
==================

.. module:: hpilo

The :py:mod:`hpilo` module contains all you need to communicate with iLO
devices, encapsulated in the :class:`Ilo` class and its methods. There are a
few auxiliarry items in this module too.

.. py:class:: Ilo(hostname, login=None, password=None, timeout=60, port=443, protocol=None, delayed=False, ssl_verify=False, ssl_context=None)

   Represents an iLO management interface on a specific host.

   :param hostname: Hostname or IP address of the iLO interface
   :param login: Loginname to use for authentication, not used for :py:data:`LOCAL` connections
   :param password: Password to use for authentication, not used for :py:data:`LOCAL` connections
   :param timeout: Timeout for creating connections or receiving data
   :param port: TCP port to use for HTTPS connections
   :param protocol: The protocol to use. Either :py:data:`hpilo.RAW` for remote
                    iLO2 or older, :py:data:`hpilo.HTTP` for remote ilo3 and
                    newer or :py:data:`hpilo.LOCAL` for using
                    :program:`hponcfg` and the local kernel driver. If you do
                    not specify this parameter, it will be autodetected.
   :param delayed: By default, this library will immediately contact the iLO
                   for any method call you make and return a result. To save
                   roundtrip time costs, set this to :py:data:`False` and call
                   the :py:meth:`call_delayed` method manually.
   :param ssl_verify: By default, this library does not verify ssl
                   certificates, because the iLO comes with a self-signed
                   certificate by default and sadly not many people fix this.
                   But if you do fix this, you can actually force verification
                   of the certificates.
   :param ssl_context: If you need custom ssl or verification parameters, such
                   as a custom CA certificate, you can pass a custom ssl
                   context object with all the settings you need.

   .. py:method:: call_delayed

      Calls all the delayed methods that have accumulated. This is best
      illustrated with an example. Observe the difference between:

          >>> ilo = hpilo.Ilo('example-server.int.kaarsemaker.net', 'Administrator', 'PassW0rd')
          >>> pprint(ilo.get_fw_version())
          {'firmware_date': 'Aug 26 2011',
           'firmware_version': '1.26',
           'license_type': 'iLO 3 Advanced',
           'management_processor': 'iLO3'}
          >>> pprint(ilo.get_uid_status())
          'OFF'
          >>> ilo = hpilo.Ilo('example-server.int.kaarsemaker.net', 'Administrator', 'PassW0rd', ssl_version=ssl.PROTOCOL_TLSv1_2)
          {'firmware_date': 'Dec 02 2015',
           'firmware_version': '2.40',
           'license_type': 'iLO Standard',
           'management_processor': 'iLO4'}

      and

          >>> ilo = hpilo.Ilo('example-server.int.kaarsemaker.net', 'Administrator',
          ...                 'PassW0rd', delayed=True)
          >>> pprint(ilo.get_fw_version())
          None
          >>> pprint(ilo.get_uid_status())
          None
          >>> pprint(ilo.call_delayed())
          [{'firmware_date': 'Aug 26 2011',
            'firmware_version': '1.26',
            'license_type': 'iLO 3 Advanced',
            'management_processor': 'iLO3'},
           'OFF']

      The second example only contacts the iLO twice, avoiding the overhead of
      one HTTP connection. As this overhead is quite significant, it makes
      sense to do this when you need to make more than one API call.

      When using the delayed mode, please be aware that methods that trigger a
      reset may cause subsequent methods to not be called or cause errors to be
      returned for these methods.

   All other methods of this class are API calls that mimic the methods
   available via XML. These are documented separately in further pages here and
   in the `ilo scripting guide`_ published by HP.

.. py:class:: IloWarning

   A warning that is raised when the iLO returns warning messages in its XML output

.. py:class:: IloError

   An exception that is raised when the iLO or python-hpilo indicates an error
   has occured while processing your API call. For example when calling a
   method not supported by an iLO, when using invalid parameters or when the
   iLO returns unexpected data.

.. py:class:: IloCommunicationError

   Subclass of IloError that specifically indicates errors writing data to or
   reading data from the iLO.

.. py:class:: IloLoginFailed

    Subclass of IloError that indicates that you used the wrong username or
    password.

.. _`hp`: http://www.hp.com/go/ilo
.. _`ilo scripting guide`: http://www.hp.com/support/ilo4_cli_gde_en
