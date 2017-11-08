iLO licensing
=============

Several iLO features are only available if you have an iLO advanced license.
These functions can tell you whether such a license has been activated and
allow you to activate one.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_all_licenses
   .. ilo_output:: get_all_licenses
   .. automethod:: activate_license
   .. automethod:: deactivate_license
