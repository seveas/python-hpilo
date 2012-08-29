Ilo obects
==========

The :class:`Ilo` class encapsulates all functionality. It autodetects which iLO
version is in use and will send the correct messages for that version. Its
methods are divided into several categories below: getting information,
changing settings and upgrading firmware.

There are quite a few methods to get information about your server, its
enclosing chassis or the iLO board itself. To see what they return, please
refer to the :doc:`example output </output>`.

Methods that manipulate the iLO, such as setting the servers name, or changing
a users password do not have a return value.

The exception :class:`IloError` is raised in case of errors that occur when
communicating with the IlO. The subclass :class:`IloLoginFailed` is raised for
login failures.

.. py:currentmodule:: hpilo

.. autoclass:: Ilo
   :members:
