=======
Asyncme
=======

:Info: An ACME Protocol Implementation for AsyncIO
:Repository: https://github.com/ArroyoNetworks/asyncme
:Author(s): Matthew Ellison (http://github.com/seglberg)
:Maintainer(s): Matthew Ellison (http://github.com/seglberg)

.. TRAVIS CI NYI .. image:: https://travis-ci.org/ArroyoNetworks/asyncme.svg?branch=master
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

Asyncme is an AsyncIO library for interacting with the ACME (Automatic
Certificate Management Environment) protocol, such as the services offered by
Let's Encrypt.

Asyncme allows interaction with ACME servers using asynchronous http
connections, useful for larger async applications that may need to requisition
certificates automatically.

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

- None yet.

Challenges
==========

Asyncme is a library first, and a client second. What this means is that
Asyncme does not focus on automatically fulfilling ACME challenges.

However, Asyncme does provide a mechanism for satisfying challenges, and will
soon include a reference implementation for using libcloud to fulfill the
DNS-01 challenge.

Challenge objects have two primary methods:

- `perform`
- `answer`

If the specific challenge is not supported, you may simply omit calling the
`perform()` method and have your application satisfy the challenge manually.
Once you have completed satisfying the challenge, you can then call `answer()`
to alert the ACME sever to the fact you have fulfilled the challenge.

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
