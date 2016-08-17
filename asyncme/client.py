# --------------------------------------------------------------------------- #


import asyncio
import functools
import inspect
import logging
import os

from acme import errors, jose, messages
from acme.client import Client, ClientNetwork

from arroyo import crypto

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import OpenSSL

from asyncme import __version__ as ASYNCME_VERSION
from asyncme import challenges


# --------------------------------------------------------------------------- #

# Typing Imports

from typing import Union, Dict

_T_OPTL_STR = Union[str, None]
_T_CHALL_DICT = Dict[challenges.ChallengeType, messages.ChallengeBody]
_T_AIO_LOOP = asyncio.AbstractEventLoop


# --------------------------------------------------------------------------- #


LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class ExecutorClient:
    """
    Drop-in replacement for ``acme.client.Client`` that wraps blocking calls
    with coroutines that use an executor.

    The only difference difference between this client and the upstream one is
    that this client should be instantiated uses the ``connect`` coroutine,
    instead of directly.

    ``client =  ExecutorClient.connect(directory=acme_directory, key=jwk_key)``
    """

    @classmethod
    async def connect(cls, *args, loop: asyncio.AbstractEventLoop = None,
                      **kwargs) -> "ExecutorClient":
        """
        Create and connect a client to the given ACME directory with the given
        key. This coroutine should always be used for creating new clients,
        rather than instantiating the class directly, as it creates
        a blocking call (specifically during the init method of the upstream
        client).

        :param args: Arguments to be passed directly into the init of
         ``acme.client.Client``.
        :param loop: Async. loop used, uses the default loop if set to
         ``None``. Defaults to ``None``.
        :param kwargs: Keyword arguments to be passed directly into the init
         of ``acme.client.Client``.

        :return: A new instance of ``ExecutorClient``.
        """
        loop = loop or asyncio.get_event_loop()
        client = await loop.run_in_executor(
            None,
            functools.partial(Client, *args, **kwargs)
        )
        return cls(client, loop=loop)

    def __init__(self, client: Client, *,
                 loop: asyncio.AbstractEventLoop = None):
        """
        Initializes a new ACME client.

        .. warning::

            Do NOT use this method directly. All instances of
            ``ExecutorClient`` should be created through its ``connect``
            method. This is due to a blocking call made in the
            ``acme.client.Client`` init method when it verifies the ACME
            directory URI.

        :param client: Underlying ``acme.client.Client``.
        :param loop:  Async. loop used.
        """
        self._client = client
        self._loop = loop or asyncio.get_event_loop()

    def __getattr__(self, item):
        # This method wraps the underlying client and wraps any method
        # calls in an executor call.
        try:
            attr = getattr(self._client, item)
        except AttributeError as e:
            raise AttributeError(e)

        if inspect.ismethod(attr) and not inspect.iscoroutinefunction(attr):

            @functools.wraps(attr)
            async def wrapped(*args, **kwargs):
                return await self._loop.run_in_executor(
                    None,
                    functools.partial(attr, *args, **kwargs)
                )
            return wrapped

        return attr

    @property
    def loop(self):
        return self._loop


# --------------------------------------------------------------------------- #


class ExtendedNetwork(ClientNetwork):
    """
    Used to add additional functionality to the upstream ACME client.
    """
    def post(self, url, obj, content_type=ClientNetwork.JSON_CONTENT_TYPE,
             checked=True, **kwargs):

        data = self._wrap_in_jws(obj, self._get_nonce(url))
        response = self._send_request('POST', url, data=data, **kwargs)
        self._add_nonce(response)
        if checked:
            return self._check_response(response, content_type=content_type)
        else:
            return response


class AcmeCert(crypto.x509Cert):
    """
    Subclass of ``arroyo.crypto.x509Cert`` that adds a `location` attribute
    which refers to the ACME URI location of the certificate.

    TODO: Add a "from_location" class method to load a certificate from
          a given location.
    """

    def __init__(self, *args, acme_uri, **kwargs):
        super().__init__(*args, **kwargs)
        self._location = acme_uri

    @property
    def location(self):
        return self._location


class AsyncmeClient:
    """
    A high-level and asynchronous ACME client.

    .. note::

        This class is NOT intended to be a drop in replacement for
        ``acme.client.Client``. If you desire more control of the ACME
        interactions, but still require an async. client, consider using
        ``ExecutorClient`` instead.

    This class should NOT be instantiated directly, but through its
    ``connect`` method instead.


    :ivar _client: Internal client used to interact with the ACME server.
    :ivar _regr: Underlying server registration object.
    """

    @classmethod
    async def connect(cls, directory: str, key: crypto.PrivateKey, *,
                      loop: _T_AIO_LOOP = None) -> 'AsyncmeClient':
        """
        Connect to an ACME server.

        :param directory: The URI of the ACME server's directory.
        :param key: Private key used for interacting with the ACME server.
        :param loop: Event loop.

        :return: A new instance of ``AsyncmeClient`` which has been
         registered against the given ACME server, if the key has not already
         been registered.
        """

        # Determine the JWS 'alg' Type for the Given Key
        # RSA
        if key.algorithm is crypto.KeyAlgorithmType.RSA:
            if key.size/8 == 256:
                alg = jose.jwa.RS256
            elif key.size/8 == 384:
                alg = jose.jwa.RS384
            elif key.size/8 == 512:
                alg = jose.jwa.RS512
            else:
                raise ValueError("RSA key size of {} "
                                 "is unsupported".format(key.size))

        # ECDSA
        elif key.algorithm is crypto.KeyAlgorithmType.ECDSA:
            if key.size == 256:
                alg = jose.jwa.ES256
            elif key.size == 384:
                alg = jose.jwa.ES384
            elif key.size == 521:
                alg = jose.jwa.ES512
            else:
                raise ValueError("ECDSA key size of {} "
                                 "is unsupported".format(key.size))

        # Other
        else:
            raise ValueError("Unsupported private key type, must "
                             "be RSA or ECDSA")

        # Convert Key
        password = os.urandom(255)
        acme_key = jose.JWKRSA(key=serialization.load_der_private_key(
            key.to_bytes(encoding=crypto.EncodingType.DER, password=password),
            password,
            default_backend()
        ))

        # Get Async. Loop
        loop = loop or asyncio.get_event_loop()

        # Instantiate Underlying Client
        # (and make the initial connection to the ACME server)
        try:
            client = await ExecutorClient.connect(
                directory=directory,
                key=acme_key,
                alg=alg,
                net=ExtendedNetwork(
                    key=acme_key,
                    alg=alg,
                    user_agent='asyncme-python-{}'.format(ASYNCME_VERSION)
                ),
                loop=loop
            )
        except TypeError:
            raise ValueError("Invalid ACME directory given")

        # Client Registration
        try:
            regr = await client.register()
        except errors.Error as e:

            # The upstream client currently has no way to "recover" a lost
            # registration resource, thus we must resort to the tactics below.

            if "key is already in use" in str(e):

                LOG.debug("Key already in use: attempting to recover "
                          "registration resource.")

                # (1) Send a Post in Attempt to Register the Client
                #     and Get a 409 Back in Response with Location
                #     Header set.

                post = functools.partial(
                    client.net.post,
                    client.directory['new-reg'],
                    messages.NewRegistration(),
                    checked=False
                )
                response = await loop.run_in_executor(None, post)
                assert response.status_code == 409

                # (2) Manually create a new Registration Resource and
                #     send an empty registration update.
                #     (per draft-ietf-acme-acme-03#section-6.2)

                regr = messages.RegistrationResource(
                    uri=response.headers.get("location")
                )

                # Empty Update
                regr = await client._send_recv_regr(
                    regr,
                    body=messages.UpdateRegistration()
                )

            else:
                raise RuntimeError(e)

        return cls(client, regr)

    def __init__(self, client: ExecutorClient,
                 registration: messages.RegistrationResource):
        """
        Initializes a new ``AsyncmeClient``

        Generally, new instances should be created through the ``connect``
        method to avoid blocking calls.

        :param client: The underlying ``ExecutorClient``.
        :param registration: The ACME account's registration object.
        """

        self._client = client
        self._regr = registration

    @property
    def agreement(self) -> _T_OPTL_STR:
        """
        The client's current agreement.
        Typically empty (``None``) if no agreement has been made.
        """
        return self._regr.body.agreement

    @property
    def terms_of_service(self) -> str:
        """
        URI to the ACME server's terms of service.
        """
        return self._regr.terms_of_service

    async def accept_terms(self) -> None:
        """
        Accept the ACME server's terms of service.
        """
        self._regr = await self._client.agree_to_tos(self._regr)

    async def get_domain_challenges(self, domain: str) -> _T_CHALL_DICT:
        """
        Returns ACME challenges for the given domain.

        :param domain: Domain to return challenges for.

        :return: A ``dict`` whose keys are the challenge types, with values
         corresponding to the actual challenges.
        """
        authzr = await self._client.request_domain_challenges(domain)
        return {
            challenges.ChallengeType(c.typ):
                challenges.AcmeChallenge(c, self._client)
            for c in authzr.body.challenges
        }

    def has_accepted_terms(self) -> bool:
        """
        :return: ``True`` if the client has accept the terms of services
         for the ACME server. ``False`` otherwise.
        """
        return self.agreement == self.terms_of_service

    async def is_authed_for_domain(self, domain: str) -> bool:
        """
        Determine if the client is authorized to generate a certificate
        for the given domain.

        :param domain: The domain to check.

        :return: ``True`` if the client is authorized. Otherwise ``False``.
        """
        # XXX: Technically this doesn't check "combinations".
        authzr = await self._client.request_domain_challenges(domain)
        return any(chall.status == messages.STATUS_VALID
                   for chall in authzr.body.challenges)

    async def request_cert(self, csr: crypto.x509CertSignReq) -> AcmeCert:
        """
        Request the issuance of a certificate for the given CSR.

        :param csr: The CSR to fulfill.

        :return: The newly issued x509 certificate.
        """

        # (1) First get a list of the authorization resources in the CSR
        #     by inspecting the SAN (we current do not look at the CN)
        domains = csr.get_subj_alt_dns_names()
        authzrs = []

        for domain in domains:
            new_authzr = await self._client.request_domain_challenges(domain)
            authzrs.append(new_authzr)

        # (2) Convert the CSR
        acme_csr = jose.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_PEM,
                csr.to_bytes(encoding=crypto.EncodingType.PEM)
            )
        )

        # (3) Request the Issuance
        acme_cert = await self._client.request_issuance(acme_csr, authzrs)
        py_openssl_cert = acme_cert.body.wrapped

        # (4) Covert the Issuance Object
        cert = AcmeCert(
            OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM,
                py_openssl_cert
            ),
            acme_uri=acme_cert.uri
        )

        return cert
