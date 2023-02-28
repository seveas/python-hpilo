Unauthenticated iLO and Chassis OA data
=======================================
Unless you have disabled it, both server/blade iLO's and chassis onboard
administrators, expose a lot of basic information on an unauthenticated https
url. While not technically part of the iLO API, this is still a useful function
to have, and is the only way to programmatically get data from an onboard
Administrator.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: xmldata
   .. ilo_output:: xmldata
