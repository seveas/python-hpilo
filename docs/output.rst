Example output of API calls
===========================

This document describes the return value of :class:`hpilo.Ilo` API calls that
return something.

.. note::

  As not all devices support all methods, the sample output does not all
  originate from the same server. The data has also been anonymised.

.. function:: get_ahs_status()
  :noindex:

  >>> pprint(my_ilo.get_ahs_status())
  {'ahs_hardware_status': 'ENABLED', 'ahs_status': 'DISABLED'}

.. function:: get_all_licenses()
  :noindex:

  >>> pprint(my_ilo.get_all_licenses())
  [{'license_class': 'FQL',
    'license_install_date': 'Tue Oct  8 22:51:16 2013',
    'license_key': 'XXXXX-XXXXX-XXXXX-XXXXX-XXXXX',
    'license_type': 'iLO 4 Advanced'}]

.. function:: get_all_users()
  :noindex:

  >>> pprint(my_ilo.get_all_users())
  ['Administrator']

.. function:: get_all_user_info()
  :noindex:

  >>> pprint(my_ilo.get_all_user_info())
  {'Administrator': {'admin_priv': True,
                     'config_ilo_priv': True,
                     'remote_cons_priv': True,
                     'reset_server_priv': True,
                     'user_login': 'Administrator',
                     'user_name': 'Administrator',
                     'virtual_media_priv': True}}

.. function:: get_asset_tag()
  :noindex:

  >>> pprint(my_ilo.get_asset_tag())
  /home/dennis/code/python-hpilo/hpilo.py:459: IloWarning: No Asset Tag Information.
    warnings.warn(child.get('MESSAGE'), IloWarning)
  {'asset_tag': None}

  >>> pprint(my_ilo.get_asset_tag())
  {'asset_tag': 'NL00001'}


.. function:: get_cert_subject_info()
  :noindex:

  >>> pprint(my_ilo.get_cert_subject_info())
  {'csr_subject_common_name': 'example-server.int.kaarsemaker.net',
   'csr_subject_country': 'US',
   'csr_subject_location': 'Houston',
   'csr_subject_org_name': 'Hewlett-Packard Development Company',
   'csr_subject_orgunit_name': 'ISS',
   'csr_subject_state': 'Texas',
   'csr_use_cert_2048pkey': 'NO',
   'csr_use_cert_custom_subject': 'NO',
   'csr_use_cert_fqdn': 'YES'}

.. function:: get_dir_config()
  :noindex:

  >>> pprint(my_ilo.get_dir_config())
  {'dir_authentication_enabled': False,
   'dir_enable_grp_acct': False,
   'dir_local_user_acct': True,
   'dir_object_dn': '',
   'dir_server_address': '',
   'dir_server_port': 636,
   'dir_user_context_1': '',
   'dir_user_context_2': '',
   'dir_user_context_3': ''}

.. function:: get_embedded_health()
  :noindex:

  >>> pprint(my_ilo.get_embedded_health())
  {'fans': {'Fan 1': {'label': 'Fan 1',
                      'speed': (13, 'Percentage'),
                      'status': 'OK',
                      'zone': 'System'},
           (Additional fans removed from sample output)
                                      },
   'health_at_a_glance': {'fans': {'redundancy': 'REDUNDANT', 'status': 'OK'},
                          'power_supplies': {'redundancy': 'REDUNDANT',
                                             'status': 'OK'},
                          'temperature': {'status': 'OK'}},
   'power_supplies': {'Power Supply 1': {'label': 'Power Supply 1',
                                         'status': 'OK'},
                      'Power Supply 2': {'label': 'Power Supply 2',
                                         'status': 'OK'}},
   'temperature': {'Ambient': {'caution': (41, 'Celsius'),
                               'critical': (45, 'Celsius'),
                               'currentreading': (23, 'Celsius'),
                               'label': 'Temp 1',
                               'location': 'Ambient',
                               'status': 'OK'},
                  (Additional temperature readings removed from sample output)
                                             },
   'vrm': None}

.. function:: get_ers_settings()
  :noindex:

  >>> pprint(my_ilo.get_ers_settings())
  {'ers_agent': '',
   'ers_collection_frequency': 'P30D',
   'ers_connect_model': 0,
   'ers_destination_port': 0,
   'ers_destination_url': '',
   'ers_last_transmission_date': '-',
   'ers_last_transmission_errno': 'No error',
   'ers_last_transmission_type': 0,
   'ers_state': 0,
   'ers_web_proxy_port': 0,
   'ers_web_proxy_url': '',
   'ers_web_proxy_username': ''}

.. function:: get_federation_multicast()
  :noindex:

  >>> pprint(my_ilo.get_federation_multicast())
  {'ipv6_multicast_scope': 'Site',
   'multicast_announcement_interval': 'Disabled',
   'multicast_discovery_enabled': 'No',
   'multicast_ttl': 5}

.. function:: get_fips_status()
  :noindex:

  >>> pprint(my_ilo.get_fips_status())
  {'fips_mode': 'Enabled'}

.. function:: get_fw_version()
  :noindex:

  >>> pprint(my_ilo.get_fw_version())
  {'firmware_date': 'Mar 19 2009',
   'firmware_version': '1.94',
   'management_processor': 'iLO'}

.. function:: get_global_settings()
  :noindex:

  >>> pprint(my_ilo.get_global_settings())
  {'authentication_failure_logging': 'Enabled-every 3rd failure',
   'enforce_aes': False,
   'f8_login_required': False,
   'f8_prompt_enabled': True,
   'http_port': 80,
   'https_port': 443,
   'ilo_funct_enabled': True,
   'min_password': 8,
   'rbsu_post_ip': True,
   'remote_console_port': 17990,
   'serial_cli_speed': 9600,
   'serial_cli_status': 'Enabled-Authentication Required',
   'session_timeout': 30,
   'ssh_port': 22,
   'ssh_status': True,
   'virtual_media_port': 17988}

.. function:: get_host_data(decoded_only=True)
  :noindex:

  >>> pprint(my_ilo.get_host_data())
  [{'Date': '03/01/2006',
    'Family': 'A05',
    'Subject': 'BIOS Information',
    'b64_data': 'ABQAAAECAPADP4DawX0AAAAAAwFIUABBMDUAMDMvMDEvMjAwNgAA',
    'type': 0},
   (Further records skipped)]

.. function:: get_host_power_saver_status()
  :noindex:

  >>> pprint(my_ilo.get_host_power_saver_status())
  {'host_power_saver': 'AUTO'}

.. function:: get_host_power_status()
  :noindex:

  >>> pprint(my_ilo.get_host_power_status())
  ON

.. function:: get_host_pwr_micro_ver()
  :noindex:

  >>> pprint(my_ilo.get_host_pwr_micro_ver())
  1.6

.. function:: get_ilo_event_log()
  :noindex:

  >>> pprint(my_ilo.get_ilo_event_log())
  [{'class': 'iLO 3',
    'count': 1,
    'description': 'Event log cleared.',
    'initial_update': '01/30/2011 16:33',
    'last_update': '01/30/2011 16:33',
    'severity': 'Informational'},
   {'class': 'iLO 3',
    'count': 1,
    'description': 'Server reset.',
    'initial_update': '01/30/2011 16:34',
    'last_update': '01/30/2011 16:34',
    'severity': 'Caution'},
   {'class': 'iLO 3',
    'count': 4,
    'description': 'Server power restored.',
    'initial_update': '01/30/2011 16:34',
    'last_update': '01/30/2011 16:42',
    'severity': 'Informational'},
    (Other log entries skipped)]

.. function:: get_language()
  :noindex:

  >>> pprint(my_ilo.get_language())
  {'lang_id': 'en', 'language': 'English'}

.. function:: get_all_languages()
  :noindex:

  >>> pprint(my_ilo.get_all_languages())
  {'lang_id': 'en', 'language': 'English'}

.. function:: get_network_settings()
  :noindex:

  >>> pprint(my_ilo.get_network_settings())
  {'dhcp_dns_server': True,
   'dhcp_domain_name': True,
   'dhcp_enable': True,
   'dhcp_gateway': True,
   'dhcp_sntp_settings': True,
   'dhcp_static_route': True,
   'dhcp_wins_server': True,
   'dns_name': '',
   'domain_name': 'ilo.kaarsemaker.net',
   'enable_nic': True,
   'full_duplex': False,
   'gateway_ip_address': '10.42.128.254',
   'ip_address': '10.42.128.100',
   'mac_address': '9c:8e:99:fb:96:12',
   'nic_speed': 10,
   'ping_gateway': True,
   'prim_dns_server': '10.42.128.1',
   'prim_wins_server': '0.0.0.0',
   'reg_ddns_server': True,
   'reg_wins_server': True,
   'sec_dns_server': '0.0.0.0',
   'sec_wins_server': '0.0.0.0',
   'shared_network_port': False,
   'sntp_server1': '10.42.128.1',
   'sntp_server2': '10.42.128.2',
   'speed_autoselect': True,
   'static_route_1': {'dest': '0.0.0.0',
                      'gateway': '0.0.0.0',
                      'mask': '0.0.0.0'},
   'static_route_2': {'dest': '0.0.0.0',
                      'gateway': '0.0.0.0',
                      'mask': '0.0.0.0'},
   'static_route_3': {'dest': '0.0.0.0',
                      'gateway': '0.0.0.0',
                      'mask': '0.0.0.0'},
   'subnet_mask': '255.255.255.0',
   'ter_dns_server': '0.0.0.0',
   'timezone': 'Europe/Amsterdam',
   'vlan_enabled': False,
   'vlan_id': 0}

.. function:: get_oa_info()
  :noindex:

  >>> pprint(my_ilo.get_oa_info())
  {'encl': 'chassis-25',
   'ipaddress': '10.42.128.101',
   'location': 1,
   'macaddress': '68:b5:99:bb:dc:85',
   'rack': 'chassis-25',
   'st': 0,
   'uidstatus': 'Off'}

.. function:: get_one_time_boot()
  :noindex:

  >>> pprint(my_ilo.get_one_time_boot())
  'normal'

.. function:: get_persistent_boot()
  :noindex:

  >>> pprint(my_ilo.get_persistent_boot())
  ['cdrom', 'floppy', 'usb', 'hdd', 'network']

.. function:: get_pers_mouse_keyboard_enabled()
  :noindex:

  >>> pprint(my_ilo.get_pers_mouse_keyboard_enabled())
  False

.. function:: get_power_cap()
  :noindex:

  >>> print(my_ilo.get_power_cap())
  OFF

.. function:: get_power_readings()
  :noindex:

  >>> pprint(my_ilo.get_power_readings())
  {'average_power_reading': (138, 'Watts'),
   'maximum_power_reading': (191, 'Watts'),
   'minimum_power_reading': (138, 'Watts'),
   'present_power_reading': (138, 'Watts')}

.. function:: get_pwreg()
  :noindex:

  >>> pprint(my_ilo.get_pwreg())
  {'efficiency_mode': 2,
   'get_host_power': {'host_power': 'ON'},
   'pcap': {'mode': 'OFF'}}

.. function:: get_rack_settings()
  :noindex:

  >>> pprint(my_ilo.get_rack_settings())
  {'bay': 9,
   'enclosure_name': 'CHASSIS-225',
   'enclosure_sn': 'CZ1234ABCD',
   'enclosure_type': 'BladeSystem c7000 Enclosure G2',
   'enclosure_uuid': '09CZ1234ABCD',
   'rack_name': 'CHASSIS-225'}

.. function:: get_security_msg()
  :noindex:

  >>> pprint(my_ilo.get_security_msg())
  {'security_msg': 'Enabled',
   'security_msg_text': 'Time is an illusion. Lunchtime doubly so'}

.. function:: get_server_auto_pwr()
  :noindex:

  >>> print(my_ilo.get_server_auto_pwr())
  RANDOM

.. function:: get_server_event_log()
  :noindex:

  >>> pprint(my_ilo.get_server_event_log())
  [{'class': 'Maintenance',
    'count': 1,
    'description': 'Maintenance note: IML cleared through hpasmcli',
    'initial_update': '01/30/2011 16:34',
    'last_update': '01/30/2011 16:34',
    'severity': 'Informational'},
   {'class': 'POST Message',
    'count': 1,
    'description': 'POST Error: 1785-Drive Array not Configured',
    'initial_update': '01/30/2011 16:37',
    'last_update': '01/30/2011 16:37',
    'severity': 'Caution'},
   {'class': 'Power',
    'count': 1,
    'description': 'System Power Supply: General Failure (Power Supply 1)',
    'initial_update': '05/05/2011 00:25',
    'last_update': '05/05/2011 00:25',
    'severity': 'Caution'},
   {'class': 'Power',
    'count': 1,
    'description': 'System Power Supplies Not Redundant',
    'initial_update': '05/05/2011 00:25',
    'last_update': '05/05/2011 00:25',
    'severity': 'Caution'}]

.. function:: get_server_fqdn()
  :noindex:

  >>> pprint(my_ilo.get_server_fqdn())
  example-server.int.kaarsemaker.net

.. function:: get_server_name()
  :noindex:

  >>> print(my_ilo.get_server_name())
  example-server.int.kaarsemaker.net

.. function:: get_server_power_on_time()
  :noindex:

  >>> pprint(my_ilo.get_server_power_on_time())
  53691

.. function:: get_snmp_im_settings()
  :noindex:

  >>> pprint(my_ilo.get_snmp_im_settings())
  {'cim_security_mask': 3,
   'os_traps': True,
   'rib_traps': True,
   'snmp_address_1': '',
   'snmp_address_2': '',
   'snmp_address_3': '',
   'snmp_passthrough_status': True,
   'web_agent_ip_address': 'example-server.int.kaarsemaker.net'}

.. function:: get_spatial()
  :noindex:

  >>> pprint(my_ilo.get_spatial())
  {'bay': 9,
   'cuuid': '4dc3b42a-3d64-41c9-8832-fce93df1838b',
   'discovery_data': 'Unknown data',
   'discovery_rack': 'Not Supported',
   'enclosure_cuuid': '699b6ec0-d98c-4587-a633-58f33839455d'm
   'enclosure_sn': 'CZ1234ABCD',
   'platform': 'BL',
   'rack_description': 0,
   'rack_id': 0,
   'rack_id_pn': 0,
   'rack_uheight': 0,
   'tag_version': 0,
   'uheight': 0,
   'ulocation': 0,
   'uoffset': 0,
   'uposition': 0}

.. function:: get_sso_settings()
  :noindex:

  >>> pprint(my_ilo.get_sso_settings())
  {'administrator_role': {'admin_priv': True,
                          'cfg_ilo_priv': True,
                          'login_priv': True,
                          'remote_cons_priv': True,
                          'reset_server_priv': True,
                          'virtual_media_priv': True},
   'operator_role': {'admin_priv': False,
                     'cfg_ilo_priv': False,
                     'login_priv': True,
                     'remote_cons_priv': True,
                     'reset_server_priv': True,
                     'virtual_media_priv': True},
   'trust_mode': 'DISABLED',
   'user_role': {'admin_priv': False,
                 'cfg_ilo_priv': False,
                 'login_priv': True,
                 'remote_cons_priv': False,
                 'reset_server_priv': False,
                 'virtual_media_priv': False}}

.. function:: get_twofactor_settings()
  :noindex:

  >>> pprint(my_ilo.get_twofactor_settings())
  {'auth_twofactor_enable': False,
   'cert_owner_subject': None,
   'cert_revocation_check': False}

.. function:: get_uid_status()
  :noindex:

  >>> print(my_ilo.get_uid_status())
  OFF

.. function:: get_user(user_login)
  :noindex:

  >>> pprint(my_ilo.get_user(user_login="Administrator"))
  {'admin_priv': True,
   'config_ilo_priv': True,
   'remote_cons_priv': True,
   'reset_server_priv': True,
   'user_login': 'Administrator',
   'user_name': 'Administrator',
   'virtual_media_priv': True}

.. function:: get_vm_status(device="CDROM")
  :noindex:

  >>> pprint(my_ilo.get_vm_status())
  {'boot_option': 'NO_BOOT',
   'device': 'CDROM',
   'image_inserted': 'NO',
   'image_url': '',
   'vm_applet': 'DISCONNECTED',
   'write_protect': 'NO'}

.. function:: xmldata()
  :noindex:

  >>> pprint(my_ilo.xmldata())
  {'health': {'status': 2},
   'hsi': {'cuuid': '32333536-3030-5A43-3232-343030394A4E',
           'nics': [{'macaddr': 'ac:16:2d:ab:cd:e0', 'port': 1},
                    {'macaddr': 'ac:16:2d:ab:cd:e1', 'port': 2},
                    {'macaddr': 'ac:16:2d:ab:cd:e2', 'port': 3},
                    {'macaddr': 'ac:16:2d:ab:cd:e3', 'port': 4}],
           'productid': ' 653200-B21      ',
           'sbsn': 'CZ1234ABCD      ',
           'sp': 1,
           'spn': 'ProLiant DL380p Gen8',
           'uuid': '123456CZ1234ABCD',
           'virtual': {'state': 'Inactive',
                       'vid': {'bsn': None, 'cuuid': None}}},
   'mp': {'bblk': '08/30/2011',
          'ealert': 1,
          'ers': 0,
          'fwri': '1.22',
          'hwri': 'ASIC: 12',
          'ipm': 1,
          'pn': 'Integrated Lights-Out 4 (iLO 4)',
          'pwrm': '3.0',
          'sn': 'ILO1234ABCDEF      ',
          'sso': 0,
          'st': 1,
          'uuid': 'ILO123456CZ1234ABCD'},
   'spatial': {'cuuid': 'a37a3efd-3d6c-4798-b0de-267ac0559db5',
               'discovery_data': 'Server does not detect Discovery Services',
               'discovery_rack': 'Not Supported',
               'rack_description': 0,
               'rack_id': 0,
               'rack_id_pn': 0,
               'rack_uheight': 0,
               'tag_version': 0,
               'uheight': 200,
               'ulocation': 0,
               'uoffset': 0,
               'uposition': 0}}
