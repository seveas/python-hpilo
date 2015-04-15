Unauthenticated iLO and Chassis OA data
=======================================
Unless you have disabled it, both server/blade iLO'sand chassis onboard
administrators, expose a lot of basic information on an unauthenticated https
url. While not technically part of the iLO API, this is still a useful function
to have, and is the only way to programatically get data from an Onboard
Administrator.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: xmldata
   .. ilo_output:: xmldata
