=======
Asyncme
=======

:Info: An ACME Protocol Client for AsyncIO
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

Asyncme is an AsyncIO client and library for interacting with the ACME
(Automatic Certificate Management Environment) protocol, such as the services
offered by Let's Encrypt.

Asyncme allows interaction with ACME servers using asynchronous http
connections, useful for larger async applications that may need to acquire
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

- acme
- arroyo-crypto
- dnspython


Quick Start
===========

Asyncme includes two clients:

ExecutorClient
--------------
The executor client is a near-drop-in replacement for the official
``python-acme`` client. The only difference is that a factory method is
used. All blocking calls are replaced with coroutines that use
an asyncio loop's executor to prevent blocking.

Below is the example from ``python-acme`` rewritten to use the
``ExecutorClient``:

.. code-block:: python

    """Example script showing how to use acme client API."""
    import logging
    import os
    import pkg_resources

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    import OpenSSL

    from acme import messages
    from acme import jose

    from asyncme.client import ExecutorClient

    import asyncio


    # XXX: Assume we are already in a co-routine to simplify example.

    logging.basicConfig(level=logging.DEBUG)


    DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'
    BITS = 2048  # minimum for Boulder
    DOMAIN = 'example1.com'  # example.com is ignored by Boulder

    # generate_private_key requires cryptography>=0.5
    key = jose.JWKRSA(key=rsa.generate_private_key(
        public_exponent=65537,
        key_size=BITS,
        backend=default_backend()))
    loop = asyncio.get_event_loop()
    acme = ExecutorClient.connect(DIRECTORY_URL, key, loop=loop)

    regr = await acme.register()
    logging.info('Auto-accepting TOS: %s', regr.terms_of_service)
    await acme.agree_to_tos(regr)
    logging.debug(regr)

    authzr = await acme.request_challenges(
        identifier=messages.Identifier(typ=messages.IDENTIFIER_FQDN, value=DOMAIN),
        new_authzr_uri=regr.new_authzr_uri)
    logging.debug(authzr)

    authzr, authzr_response = await acme.poll(authzr)

    csr = OpenSSL.crypto.load_certificate_request(
        OpenSSL.crypto.FILETYPE_ASN1, pkg_resources.resource_string(
            'acme', os.path.join('testdata', 'csr.der')))
    try:
        await acme.request_issuance(jose.util.ComparableX509(csr), (authzr,))
    except messages.Error as error:
        print ("This script is doomed to fail as no authorization "
               "challenges are ever solved. Error from server: {0}".format(error))

AsyncmeClient
-------------
Asyncme provides a high-level client of its own, which leverages its own
challenge/challenge handler system.

.. code-block:: python

    import asyncio
    from arroyo import crypto

    from asyncme.client import AsyncmeClient as Client
    from asyncme.challenges import ChallengeType, ChallengeFailure
    from asyncme.handlers import LibcloudHandler

    DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'
    LOOP = asyncio.get_event_loop()
    DOMAIN = "seglberg.arroyo.io"

    AWS_ACCESS_ID = "ACCESS_ID_HERE"
    AWS_SECRET_ID = "SECRET_ID_HERE"

    ACME_KEY = crypto.PrivateKey.generate("RSA")
    CERT_KEY = crypto.PrivateKey.generate("ECDSA")

    CSR = crypto.x509CertSignReq.generate(CERT_KEY, DOMAIN)

    async def acme_test():

        client = await Client.connect(DIRECTORY_URL, key, loop=LOOP)

        if not client.has_accepted_terms():
            await client.accept_terms()

        authed = await client.is_authed_for_domain(DOMAIN)
        if not authed:

            challenges = await client.get_domain_challenges(DOMAIN)
            dns_01 = challenges[ChallengeType.DNS_01]

            creds = (AWS_ACCESS_ID, AWS_SECRET_ID)
            handler = LibcloudHandler(dns_01, DOMAIN, provider='route53',
                                      credentials=creds, loop=LOOP)

            try:
                await handler.perform()
            except ChallengeFailure:
                raise RuntimeError("Failed to satisfy ACME challenge")

            # Ensure that we gained authorization for the domain
            for _ in range(10):
                if await client.is_authed_for_domain(DOMAIN):
                    break
                await asyncio.sleep(1)
            else:
                raise RuntimeError("Failed to gain authorization for domain")

        cert = await client.request_cert(csr)

        return cert

    if __name__ == "__main__":

        certificate = LOOP.run_until_complete(acme_test())

        # Print out the URL to the cert
        print("Certificate Location: {}".format(certificate.location))
        certificate.to_file("new-cert.pem", encoding=crypto.EncodingType.PEM)


Challenges
==========

When using the ``AsyncmeClient``, challenges can be completed using Asyncme's own
challenge handlers.

Asyncme currently maintains a single handler for DNS-01 challenges, using
``apache-libcloud``.


LibcloudHandler
---------------

Ensure that ``apache-libcloud`` is installed, otherwise it can be specified
as an extra dependency when installing Asyncme.

.. code-block:: bash

    pip install asyncme[libcloud]


.. code-block:: python

    from asyncme.handlers import LibcloudHandler


By leveraging Apache Libcloud, the handler is able to automatically satisfy the DNS-01 challenge
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
