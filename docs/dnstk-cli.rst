dnstk-cli
#########

Description
===========

``dnstk-cli`` is a command line tool for making DNS queries using dnstk.

Usage
-----

| dnstk-cli [-h] [-t] [-r RESOURCE] [-c CLS] [-s SERVER] name

Optional arguments
------------------

-h, --help            show this help message and exit

-t, --tcp

-r RESOURCE, --resource RESOURCE

-c CLS, --cls CLS

-s SERVER, --server SERVER

Examples
========

Producing an AAAA query
-----------------------

.. code-block:: console

    $ dnstk-cli irc.darkscience.net -r AAAA
    Response code: 0
    Question section
    irc.darkscience.net   IN  AAAA

    Answer section
    irc.darkscience.net   IN  CNAME   irc.darkscience.ws
    irc.darkscience.ws    IN  AAAA    2a02:2770::21a:4aff:fec1:1628

Producing a query with a specific server
----------------------------------------

.. code-block:: console

    $ dnstk-cli -s 208.67.222.222 ddg.gg
    Response code: 0
    Question section
    ddg.gg IN  A

    Answer section
    ddg.gg IN  A   208.94.146.80
    ddg.gg IN  A   208.94.146.81
    ddg.gg IN  A   208.94.146.70
    ddg.gg IN  A   208.94.146.71

