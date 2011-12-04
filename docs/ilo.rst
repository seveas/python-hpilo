Ilo obects
==========

The :class:`Ilo` class encapsulates all functionality. It autodetects which iLO
version is in use and will send the correct messages for that version. Its
methods are divided into several categories below: getting information,
changing settings and upgrading firmware.

There are quite a few functions to get information about your server, its
enclosing chassis or the iLO board itself. To see what they return, please
refer to the :doc:`example output </output>`.

.. py:currentmodule:: hpilo

.. autoclass:: Ilo
   :members:
