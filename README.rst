dnstk
=====

.. image:: https://secure.travis-ci.org/kylef/dnstk.png?branch=master
    :target: http://travis-ci.org/#!/kylef/dnstk
    :alt: Travis-ci: continuous integration status.

dnstk is a toolkit for building DNS clients and servers in Python_.

dnstk-cli
---------

dnstk includes its own client which works similar to dig_::

    $ dnstk-cli ddg.gg
    Response code: NOERROR
    Question section
    ddg.gg IN  A

    Answer section
    ddg.gg IN  A   208.94.146.80
    ddg.gg IN  A   208.94.146.81
    ddg.gg IN  A   208.94.146.70
    ddg.gg IN  A   208.94.146.71

.. Links

.. _Python: http://www.python.org/
.. _dig: http://en.wikipedia.org/wiki/Dig_(command)
