Virtual media
=============

The iLO can make an iso file located on another machine available to the server
as virtual floppy or cdrom device. This can be used to e.g. install an
operating system remotely.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_vm_status
   .. ilo_output:: get_vm_status
   .. automethod:: set_vf_status
   .. automethod:: set_vm_status
   .. automethod:: insert_virtual_media
   .. automethod:: eject_virtual_floppy
   .. automethod:: eject_virtual_media
