Authentication settings
=======================

By default, an iLO has only one user account: Administrator. But via the API
you can create more users and manipulate them. It's also possible to import SSH
keys, configure kerberos settings and configure single-sign on. Some methods
accept a lot of arguments, for details on what these arguments mean, I will
refer to the `ilo scripting guide`_.

.. _`ilo scripting guide`: http://www.hp.com/support/ilo4_cli_gde_en

.. py:currentmodule:: hpilo

.. class:: Ilo
   :noindex:

   .. automethod:: get_all_users
   .. ilo_output:: get_all_users
   .. automethod:: get_all_user_info
   .. ilo_output:: get_all_user_info
   .. automethod:: get_user
   .. ilo_output:: get_user
   .. automethod:: add_user
   .. automethod:: mod_user
   .. automethod:: delete_user
   .. automethod:: import_ssh_key
   .. automethod:: delete_ssh_key
   .. automethod:: get_dir_config
   .. ilo_output:: get_dir_config
   .. automethod:: mod_dir_config
   .. automethod:: start_dir_test
   .. automethod:: get_dir_test_results
   .. ilo_output:: get_dir_test_results
   .. automethod:: abort_dir_test
   .. automethod:: get_sso_settings
   .. ilo_output:: get_sso_settings
   .. automethod:: mod_sso_settings
   .. automethod:: add_sso_server
   .. automethod:: delete_sso_server
   .. automethod:: get_twofactor_settings
   .. ilo_output:: get_twofactor_settings
   .. automethod:: mod_twofactor_settings
