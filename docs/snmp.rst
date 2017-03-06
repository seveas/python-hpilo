SNMP settings
=============
Besides looking at the :doc:`health data </health>` via this API, you can also
monitor the iLO using the standard SNMP protocol. It can even forward SNMP
requests to the host. With these functions you can tell the iLO what to do for
SNMP.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_snmp_im_settings
   .. ilo_output:: get_snmp_im_settings
   .. automethod:: mod_snmp_im_settings
   .. automethod:: send_snmp_test_trap
