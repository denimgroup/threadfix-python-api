.. image:: https://img.shields.io/pypi/v/threadfixproapi.svg
   :target: https://pypi.org/project/threadfixproapi
.. image:: https://img.shields.io/pypi/pyversions/threadfixproapi.svg
.. image:: https://img.shields.io/travis/target/threadfixproapi/master.svg
   :target: http://travis-ci.org/target/threadfixproapi
   
ThreadFix Pro API
*****************

A Python module to assist with the `ThreadFix <https://www.threadfix.it/>`__ RESTFul API to administer scan artifacts and overall ThreadFix vulnerability administration.

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
    from ThreadFixProApi import ThreadFixProAPI

    # setup threadfix connection information
    host = 'https://127.0.0.1:8443/threadfix/'
    api_key = 'your_api_key_from_threadfix_professional'

    # initialize threadfix pro api module
    tfp = ThreadFixProAPI(host, api_key)

    # If you need to disable certificate verification.
    # tfp = ThreadFixProAPI(host, api_key, verify_ssl=False)

    # List your threadfix pro teams
    teams = tfp.Applications.TeamsAPI.list_teams()
    if teams.success:
        print("{}".format(teams.data))

        for team in teams.data:
            print(team['name'])  # Print the name of each team
    else:
        print("ERROR: {}".format(teams.message))

Supporting information for each method available can be found in the `documentation <https://target.github.io/threadfixapi/>`__.

Bugs and Feature Requests
~~~~~~~~~~~~~~~~~~~~~~~~~

Found something that doesn't seem right or have a feature request? `Please open a new issue <https://github.com/denimgroup/threadfix-python-api/issues/new>`__.

Copyright and License
~~~~~~~~~~~~~~~~~~~~~
.. image:: https://img.shields.io/github/license/target/threadfixproapi.svg?style=flat-square

- Copyright 2020 Denim Group, Ltd. (based upon work by Target Brands, Inc.)
