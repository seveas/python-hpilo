Network settings
================
By default, iLO interfaces will try to use DHCP for network configuration. With
these functions you can inspect the network configuration and, if DHCP doesn't
quite do the right thing for you, make manual adjustments.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_network_settings
   .. ilo_output:: get_network_settings
   .. automethod:: mod_network_settings
