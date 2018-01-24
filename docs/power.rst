Power manipulation
==================

The power settings and usage of to the server can be inspected using these
methods. It is also possible to power the server on and off via the iLO, and to
:doc:`boot documentation </boot>`.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: press_pwr_btn
   .. automethod:: hold_pwr_btn
   .. automethod:: get_host_power_status
   .. ilo_output:: get_host_power_status
   .. automethod:: get_host_power_reg_info
   .. automethod:: set_host_power
   .. automethod:: get_server_auto_pwr
   .. ilo_output:: get_server_auto_pwr
   .. automethod:: set_server_auto_pwr
   .. automethod:: get_critical_temp_remain_off
   .. ilo_output:: get_critical_temp_remain_off
   .. automethod:: set_critical_temp_remain_off
   .. automethod:: get_power_readings
   .. ilo_output:: get_power_readings
   .. automethod:: get_server_power_on_time
   .. ilo_output:: get_server_power_on_time
   .. automethod:: clear_server_power_on_time
   .. automethod:: get_host_power_saver_status
   .. ilo_output:: get_host_power_saver_status
   .. automethod:: set_host_power_saver
   .. automethod:: get_power_cap
   .. ilo_output:: get_power_cap
   .. automethod:: set_power_cap
   .. automethod:: get_host_pwr_micro_ver
   .. ilo_output:: get_host_pwr_micro_ver
   .. automethod:: get_pwreg
   .. ilo_output:: get_pwreg
   .. automethod:: set_pwreg
