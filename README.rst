=======
Asyncme
=======

:Info: An ACME Protocol Implementation for AsyncIO
:Repository: https://github.com/ArroyoNetworks/asyncme
:Author(s): Matthew Ellison (http://github.com/seglberg)
:Maintainer(s): Matthew Ellison (http://github.com/seglberg)

.. image:: https://travis-ci.org/ArroyoNetworks/asyncme.svg?branch=master
    :target: https://travis-ci.org/ArroyoNetworks/asyncme

.. image:: https://img.shields.io/codecov/c/github/ArroyoNetworks/asyncme/master.svg?maxAge=2592000
    :target: https://codecov.io/github/ArroyoNetworks/asyncme?branch=master

.. image:: https://img.shields.io/pypi/v/asyncme.svg
    :target: https://pypi.python.org/pypi/asyncme/

.. image:: https://img.shields.io/github/license/ArroyoNetworks/asyncme.svg
    :target: https://github.com/ArroyoNetworks/asyncme/blob/master/LICENSE


Introduction
============

.. contents:: Quick Start
   :depth: 2

.. warning::

    This library is extremely new, use at your own risk. Expect large
    changes and refactoring. Test coverage is actively being added.

------------------

Asyncme is an AsyncIO library for interacting with the ACME (Automatic
Certificate Management Environment) protocol, such as the services offered by
Let's Encrypt.

Asyncme allows interaction with ACME servers using asynchronous http
connections, useful for larger async applications that may need to requisition
certificates automatically.

First class support for the dns-01 challenge is included, and can automatically
satisfy the challenge for a large number of providers. See the `Challenges`_
section for more information.


Installation
============
Asyncme is now available on PyPI:

.. code:: console

    $ pip install asyncme

Dependencies
============
Python 3.5 or greater

Required
--------

- aiohttp
- cryptography
- jwcrypto

Extras
------

Dependencies needed for ``contrib``:

- apache-libcloud


Examples
========

1. Connect a client to an ACME endpoint

.. code:: python

    from asyncme import AcmeClient, AsymmetricKey
    import asyncio

    loop = asyncio.get_event_loop()

    # 1st - Load the ACME Account Key
    account_key = AsymmetricKey.from_pem_file("my-acme-account.pem")

    # 2nd - Create a new ACME Client
    client = AcmeClient(key, loop=loop)

    # 3rd - Connect to an ACME Server via its Directory URL
    # The Client will automatically be registered.
    loop.run_until_complete(
        client.connect(""https://acme-staging.api.letsencrypt.org/directory")
    )


2. Request a Challenge for a Domain

.. code:: python

    challenges = loop.run_until_complete(
        client.get_challenges(domain="example.com")
    )

    dns_challenge = challenges['dns-01']

    # Perform DNS Validation Manually
    # (Automatic record provisioning will be made available in the future.)
    auth_key = dns_challenge.key_authorization

    # Answer the Challenge
    loop.run_until_complete(dns_challenge.answer())


3. Request a Certificate

.. code:: python

    # Client expects raw CSR bytes in DER format (NOT PEM).
    csr = <load csr>

    # Client returns new cert as raw DER bytes.
    new_cert = loop.run_until_complete(client.get_cert(csr))


Challenges
==========

Asyncme is a library first, and a client second. What this means is that
Asyncme does not focus on automatically fulfilling ACME challenges.

However, a facility is provided for implementing automatically handling
challenges, using the ``asyncme.acme.challenges.AcmeChallengeHandler`` class.

dns-01
------

A contributed example Challenge Handler for satisfying 'dns-01' challenges
is provided: ``asyncme.contrib.challenge_handlers.LibCloudDNSHandler``.

This handler provides support for the following DNS providers:

- AURORADNS
- CLOUDFLARE
- DIGITAL_OCEAN
- DNSIMPLE
- DURABLEDNS
- GANDI
- GODADDY
- GOOGLE
- HOSTVIRTUAL
- LINODE
- LIQUIDWEB
- POINTDNS
- RACKSPACE
- RACKSPACE_UK
- RACKSPACE_US
- ROUTE53
- SOFTLAYER
- VULTR
- WORLDWIDEDNS
- ZERIGO
- ZONOMI
