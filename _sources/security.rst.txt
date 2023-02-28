Security and SSL settings
=========================

With these functions, you can ensure your iLO's security settings are as secure
as you want them, including using proper SSL certificates for communication.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: cert_fqdn
   .. automethod:: get_cert_subject_info
   .. ilo_output:: get_cert_subject_info
   .. automethod:: certificate_signing_request
   .. automethod:: import_certificate
   .. automethod:: computer_lock_config
   .. automethod:: fips_enable
   .. automethod:: get_encrypt_settings
   .. ilo_output:: get_encrypt_settings
   .. automethod:: mod_encrypt_settings
   .. automethod:: get_fips_status
   .. ilo_output:: get_fips_status
   .. automethod:: get_security_msg
   .. ilo_output:: get_security_msg
   .. automethod:: set_security_msg
   .. automethod:: get_tpm_status
   .. ilo_output:: get_tpm_status
