=======
Asyncme
=======

:Info: An ACME Protocol Implementation for AsyncIO
:Repository: https://github.com/ArroyoNetworks/asyncme
:Author(s): Matthew Ellison (http://github.com/seglberg)
:Maintainer(s): Matthew Ellison (http://github.com/seglberg)

.. image:: https://travis-ci.org/ArroyoNetworks/asyncme.svg?branch=master
    :target: https://travis-ci.org/ArroyoNetworks/asyncme
    
.. image:: https://img.shields.io/codecov/c/github/ArroyoNetworks/asyncme/master.svg?maxAge=600
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
- dnspython


Examples
========

1. Connect a client to an ACME endpoint:

   .. code:: python
    
        from asyncme import AcmeClient
        from arroyo.crypto import PrivateKey
        import asyncio
    
        loop = asyncio.get_event_loop()
        
        # 1st - Load the ACME Account Key
        account_key = PrivateKey.from_file("my-acme-account.pem")
        
        # 2nd - Create a new ACME Client
        client = AcmeClient(account_key, loop=loop)
        
        # 3rd - Connect to an ACME Server via its Directory URL
        # The Client will automatically be registered.
        loop.run_until_complete(
            client.connect("https://acme-staging.api.letsencrypt.org/directory")
        )


2. Request a Challenge for a Domain:

   .. code:: python
    
        from asyncme.plugins.challenge_handlers import DNS01ChallengeHandler
    
        challenges = loop.run_until_complete(
            client.get_challenges(domain="example.com")
        )
    
        handler = DNS01ChallengeHandler(challenges['dns-01'])
    
        # Perform DNS Validation Manually with the Needed TXT Record Contents
        # (Automatic record provisioning is available with asyncme-libcloud)
        record_name = handler.txt_record_name()
        record_contents = handler.txt_record_contents()
        
        # <Go Add Record>
    
        # Answer the Challenge
        loop.run_until_complete(handler.perform())


3. Request a Certificate:

   .. code-block:: python
    
        # Client expects raw CSR bytes in DER format (NOT PEM).
        csr = <Load CSR DER Bytes>
    
        # Client returns new cert as raw DER bytes.
        new_cert = loop.run_until_complete(client.get_cert(csr))


Challenges
==========

Asyncme is a library first, and a client second. What this means is that
Asyncme does not focus on automatically fulfilling ACME challenges.

However, a facility is provided for implementing automatically handling
challenges, using plugins that subclass
``asyncme.plugins.challenge_handlers.AcmeChallengeHandler``.

dns-01
------

We have created an example plugin `asyncme-libcloud <https://github.com/ArroyoNetworks/asyncme-libcloud>`_.

By leveraging Apache Libcloud, the plugin is able to automatically satisfy the DNS-01 challenge
for the following providers (complete list `here <https://libcloud.readthedocs.io/en/latest/dns/supported_providers.html>`_):

- AuroraDNS
- BuddyNS DNS
- CloudFlare DNS
- DigitalOcean
- DNSimple
- DurableDNS
- Gandi DNS
- GoDaddy DNS
- Google DNS
- Host Virtual DNS
- Lineode DNS
- Liquidweb DNS
- Luadns
- NFSN DNS
- NS1 DNS
- Rackspace DNS
- Amazon Route53
- Softlayer DNS
- Vultr DNS
- World Wide DNS
- Zerigo DNS
- Zonomi DNS

See `asyncme-libcloud <https://github.com/ArroyoNetworks/asyncme-libcloud>`_ for more information.
