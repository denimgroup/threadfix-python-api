ThreadFix Pro API
*****************

A Python module to assist with the `ThreadFix Professional <https://www.threadfix.it/>`__ RESTFul API to administer scan artifacts and overall ThreadFix vulnerability administration.

Quick Start
~~~~~~~~~~~

Several quick start options are available:

- Install with pip: ``pip install threadfixproapi``
- Build locally: ``python setup.py install``
- `Download the latest release <https://github.com/denimgroup/threadfix-python-api/releases/new/>`__.

Example
~~~~~~~

::

    # import the package
    from threadfixproapi import threadfixpro

    # setup threadfix connection information
    host = 'https://127.0.0.1:8443/threadfix/'
    api_key = 'your_api_key_from_threadfix_professional'

    # initialize threadfix pro api module
    tfp = threadfixpro.ThreadFixProAPI(host, api_key)

    # If you need to disable certificate verification.
    # tfp = threadfixpro.ThreadFixProAPI(host, api_key, verify_ssl=False)

    # List your threadfix pro teams
    teams = tfp.list_teams()
    if teams.success:
        print("{}".format(teams.data))

        for team in teams.data:
            print(team['name'])  # Print the name of each team
    else:
        print("ERROR: {}".format(teams.message))

Supporting information for each method available can be found in the `documentation <https://github.com/denimgroup/threadfix-python-api>`__.

Bugs and Feature Requests
~~~~~~~~~~~~~~~~~~~~~~~~~

Found something that doesn't seem right or have a feature request? `Please open a new issue <https://github.com/denimgroup/threadfix-python-api/issues/new>`__.

Copyright and License
~~~~~~~~~~~~~~~~~~~~~
.. image:: https://img.shields.io/github/license/denimgroup/threadfix-python-api.svg?style=flat-square

- Copyright 2020 Denim Group, Inc.
