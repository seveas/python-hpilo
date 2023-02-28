Automated firmware updates
==========================
Building on the :doc:`Elasticsearch </elasticsearch>` example, we can now build
automated updates for iLO firmware. 

The example application uses `beanstalk`_ and `azuki`_ to queue firmware
updates and process them with as much parallelism as you want.

Scheduling updates
------------------
If you run :command:`hpilo_firmware_update`, it will query elasticsearch to
find iLOs with obsolete firmware and schedule updates. It's probably most
useful to run this command in the same cronjob as the elasticsearch importer to
schedule firmware updates as they come in.

Checking the queue
------------------
Using the :command:`azuki` tool, you can check how many iLOs need to be upgraded::

  $ azuki stats hpilo-upgrades
  hpilo-upgrades
  Connections:
      Producers:   0
      Consumers:   1
      Waiting:     0
  Jobs:
      Delayed:     0
      Ready:       1
      Urgent:      0
      Reserved:    1
      Buried:      0
      Deleted:     11
      Total:       13

Doing the upgrades
------------------
To process the queue, you again use azuki::

   $ azuki daemon hpilo-upgrades
   INFO:azuki:Waiting for job
   Upgrading example-server-1.int.kaarsemaker.net (10.10.10.42) from ilo3 1.70 to ilo3 1.85
   ...

This will keep running and process new items as they come in. You'll probably
want to run it in screen or tmux so it stays on in the background. If you have
lots of iLOs to upgrade, you can start as many instances of this as you want,
they will not step on each others toes. I regularly run up to 30 instances in
parallel in a tmux session.

.. _`beanstalk`: http://kr.github.io/beanstalkd/
.. _`azuki`: http://github.com/seveas/azuki
