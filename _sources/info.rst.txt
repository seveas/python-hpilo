General server and iLO information
==================================

Many iLO methods allow you to retrieve information about the iLO and the server
it is built into and to manipulate basic configuration settings. This document
describes all the ones that do not fit under a more specific subject, such as
authentication or power.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: factory_defaults
   .. automethod:: force_format
   .. automethod:: get_product_name
   .. ilo_output:: get_product_name
   .. automethod:: get_fw_version
   .. ilo_output:: get_fw_version
   .. automethod:: get_host_data
   .. ilo_output:: get_host_data
   .. automethod:: get_global_settings
   .. ilo_output:: get_global_settings
   .. automethod:: mod_global_settings
   .. automethod:: get_server_name
   .. ilo_output:: get_server_name
   .. automethod:: set_server_name
   .. automethod:: get_server_fqdn
   .. ilo_output:: get_server_fqdn
   .. automethod:: set_server_fqdn
   .. automethod:: get_smh_fqdn
   .. ilo_output:: get_smh_fqdn
   .. automethod:: get_oa_info
   .. ilo_output:: get_oa_info
   .. automethod:: get_enclosure_ip_settings
   .. automethod:: get_asset_tag
   .. ilo_output:: get_asset_tag
   .. ilo_output:: get_asset_tag#1
   .. automethod:: set_asset_tag
   .. automethod:: get_uid_status
   .. ilo_output:: get_uid_status
   .. automethod:: uid_control
   .. automethod:: get_all_languages
   .. ilo_output:: get_all_languages
   .. automethod:: get_language
   .. ilo_output:: get_language
   .. automethod:: set_language
   .. automethod:: get_rack_settings
   .. ilo_output:: get_rack_settings
   .. automethod:: get_spatial
   .. ilo_output:: get_spatial
   .. automethod:: get_topology
   .. automethod:: get_diagport_settings
   .. automethod:: get_sdcard_status
   .. ilo_output:: get_sdcard_status
