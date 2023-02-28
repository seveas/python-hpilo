Server health
=============
The iLO knows a lot about your server's physical health. The
:meth:`get_embedded_health` method lets you retrieve all the health
information, so you can act upon it, for example in monitoring checks and
management scripts. Note that the returned data can differ significantly
between iLO versions.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_embedded_health
   .. ilo_output:: get_embedded_health
