Boot settings and rebooting
===========================

HP servers can boot in various ways and from many devices. The functions in
this section let you manipulate bootup settings and reboot the server and the
iLO. If you need to power off the server hard, take a look at the
:doc:`power documentation </power>`.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: reset_rib
   .. automethod:: reset_server
   .. automethod:: cold_boot_server
   .. automethod:: warm_boot_server
   .. automethod:: get_one_time_boot
   .. ilo_output:: get_one_time_boot
   .. automethod:: set_one_time_boot
   .. automethod:: get_persistent_boot
   .. ilo_output:: get_persistent_boot
   .. automethod:: set_persistent_boot
   .. automethod:: get_supported_boot_mode
   .. ilo_output:: get_supported_boot_mode
   .. automethod:: get_current_boot_mode
   .. ilo_output:: get_current_boot_mode
   .. automethod:: get_pending_boot_mode
   .. ilo_output:: get_pending_boot_mode
   .. automethod:: set_pending_boot_mode
