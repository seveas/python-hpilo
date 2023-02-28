Active Health System and Insight Remote Support
===============================================
The Active Health System and Insight Remote Support functions let you collect
information about your server environment in a central place. These functions
let you inspect and manipulate the AHS and ERS configuration and submit data.

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_ahs_status
   .. ilo_output:: get_ahs_status
   .. automethod:: set_ahs_status
   .. automethod:: ahs_clear_data
   .. automethod:: get_ers_settings
   .. ilo_output:: get_ers_settings
   .. automethod:: set_ers_irs_connect
   .. automethod:: set_ers_direct_connect
   .. automethod:: dc_registration_complete
   .. automethod:: set_ers_web_proxy
   .. automethod:: ers_ahs_submit
   .. automethod:: trigger_l2_collection
   .. automethod:: trigger_test_event
   .. automethod:: disable_ers
   .. automethod:: trigger_bb_data
