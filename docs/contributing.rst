Contributing guide
==================

python-hpilo is maintained by Dennis Kaarsemaker on GitHub_. If you have a
problem with the software, that's the place to file an issue. And if you want
to contribute to the project, that's the place to go to as well.

Patches can be submitted as pull requests on github or mailed to
dennis@kaarsemaker.net. When you submit a patch, please make sure you test it
too. The test tool is built into hpilo.py, read the comments for the _test
function to find the details. When adding new methods, please add tests too.

Coding guidelines
-----------------
* python-hpilo currently supports python 2.4 up to python 3.3. Any new code
  needs to be compatible with all these versions. That means no `with`
  statement, no `sorted` and using brackets for `print()`.
* `pep 8`_ is to be followed, except for the maximum line length rule. Be
  reasonable with your line lengths though
* All methods call into :func:`_info_tag` or :func:`_control_tag`. Any
  new method must do so too, to be able to use it in :meth:`call_delayed`.
* All new methods must be documented. A docstring is mandatory and will appear
  in the docs. For methods that return data, sample output must be added to the
  documentation too.

.. _GitHub: https://github.com/seveas/python-hpilo
.. _`pep 8`: http://www.python.org/dev/peps/pep-0008/
