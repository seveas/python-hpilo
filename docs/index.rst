Accessing HP iLO interfaces from python
=======================================

This module will make it easy for you to access the Integrated Lights Out
management interface of your HP hardware. It supports iLO, iLO 2 and iLO 3 and
It uses the XML interface to access and change the iLO.

The complete API is described in the :doc:`iLO class API reference </ilo>`. All
functions return structured data based on the XML returned by the iLO. See
:doc:`the output reference </output>` for example return values.

A command line interface to this module, :doc:`hpilo_cli </cli>` makes accessing iLO
interfaces almost trivial and easy to integrate with non-python scripts.

HP, Integrated Lights out and iLO are trademarks of HP, with whom the author of
this software is not affiliated in any way other than using some of their
hardware.

Contents:
=========

.. toctree::
   :maxdepth: 2

   ilo
   output
   cli
