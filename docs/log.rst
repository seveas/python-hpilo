iLO event log
=============
The iLO keeps two separate logs: for iLO events and for server events. While
iLO 4 can also log to a central syslog server, for others you will need to
query this log yourself, using the functions below.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_ilo_event_log
   .. ilo_output:: get_ilo_event_log
   .. automethod:: clear_ilo_event_log
   .. automethod:: get_server_event_log
   .. ilo_output:: get_server_event_log
   .. automethod:: clear_server_event_log
