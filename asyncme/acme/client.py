
import asyncio
import logging

from enum import Enum

import aiohttp

from asyncme import crypto, utils
from asyncme.acme import messages
from asyncme.acme.challenges import AcmeChallengeHandler, AcmeChallengeType


# --------------------------------------------------------------------------- #


LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class AcmeIdentifier(str, Enum):
    """
    ACME Identifier Types
    """
    DNS = "dns"


class AcmeClient:
    """
    A client used to interact with an ACME capable server.

    To use the client, it must first be connected to a server via the
    ``connect`` co-routine method.

    :ivar _loop: The ``asyncio`` event loop instance used by the client.
    """

    # The following private instance variables are available, used for
    # the client's internal implementation --

    # __priv_key:       The user supplied private key.
    # __http_session:   HTTP Session used for Async HTTP (via aiohttp).
    # __connected:      Flag used to determine if connected to a server.
    # __acme_url        URL of the ACME directory, as specified for connection.
    # __directory       Contents of the ACME server's directory index.
    # __reg_url         The URL of the Client's reg (registration) object.

    # XXX:  To be honest, the internal implementation of the client using
    # XXX:  the ACME messages (``asyncme.acme.messages``) is kind of dirty.
    # XXX:  It could use a better implementation at some point.

    def __init__(self, priv_key, *, loop=None):
        """
        Creates a new client for asynchronously interacting with an ACME
        server.

        :param priv_key: The private key used when interacting with the ACME
         server. Must be an instance of ``asyncme.crypto.PrivateKey``.
        :param loop: Set the asyncio loop used by the client. Defaults to
         ``None`` which will use the default global loop.
        """

        if not isinstance(priv_key, crypto.PrivateKey):
            raise ValueError("'priv_key' must be an instance of {}".format(
                crypto.PrivateKey
            ))
        self.__priv_key = priv_key
        self._loop = loop or asyncio.get_event_loop()

        self.__http_session = aiohttp.ClientSession(loop=self._loop)
        self.__connected = False
        self.__acme_url = None
        self.__directory = None
        self.__reg_url = None

    def __del__(self):
        if self and self.__http_session:
            self.__http_session.close()

    @property
    def priv_key(self):
        """
        Private key used by this client.

        :return: An instance of ``asyncio.crypto.PrivateKey``.
        """
        return self.__priv_key

    @priv_key.setter
    def priv_key(self, value):
        raise AttributeError("Cannot change Private Key, create a new client "
                             "instance instead.")

    @property
    def url(self):
        """
        URL of the ACME directory this client is connected to.

        :return: ``str`` containing the URL this client is connected to, or
         ``None`` if it not connected.
        """
        return self.__acme_url

    @property
    def is_connected(self):
        """
        This client's connection status.

        :return: ``True`` if the client has connected to an ACME server,
         otherwise ``False``.
        """
        return self.__connected

    async def connect(self, url):
        """
        Connect to an ACME server.

        The client will automatically be registered with the remote
        server if it has not already been.

        :param url: The URL of the directory for the ACME server to connect to.

        :returns: The client's registration information as a ``dict``.

        :raises ValueError: If the given URL is unavailable or is not a valid
         ACME directory.
        :raises RuntimeError: If the client is already connected to a server,
         even if the same URL value is given.
        """

        if self.is_connected:
            raise RuntimeError("Client is already connected to "
                               "{}".format(self.url))

        # STEP 1:   Ensure the URL is a valid ACME directory.
        if not isinstance(url, str):
            raise ValueError("'url' must be an instance of {}".format(str))

        async with self.__http_session.get(url) as response:
            try:
                self.__directory = await response.json()
            except:
                raise ValueError("{} is an invalid ACME directory".format(url))

        raw_resources = list(map(lambda v: v.value, messages.ResourceType))
        if not all(k in raw_resources for k in self.__directory):
            raise ValueError("{} did not present proper ACME functions".format(
                url
            ))

        self.__acme_url = url

        # STEP 2:   Ensure the client is registered and retrieve the client
        #           information from the server.
        reg_msg = messages.NewRegistration()
        response = await self._post_msg(reg_msg, resp_codes=(201, 409))

        self.__connected = True
        self.__reg_url = response.headers.get('location')

        # STEP 3:   Get and return the registration resource.
        return await self.get_reg()

    async def get_reg(self):
        """
        Fetches the client's registration information from the ACME server.

        :return: The client's registration information as a ``dict``.

        :raises RuntimeError: If the client is not connected to a server.
        """

        if not self.is_connected:
            raise RuntimeError("Client must be connected first")

        reg_msg = messages.Registration(url=self.__reg_url)
        response = await self._post_msg(reg_msg)

        return await response.json()

    async def get_tos(self):

        if not self.is_connected:
            raise RuntimeError("Client must be connected first")

        reg_msg = messages.Registration(url=self.__reg_url)
        response = await self._post_msg(reg_msg)

        try:
            links = response.headers.getall('link')
        except KeyError:
            return

        tos = next(l for l in links if '"terms-of-service"' in l)

        if not tos:
            return

        return tos.split(">")[0][1:]

    async def update_reg(self, *, contact=None, agreement=None):
        """
        Updates the client's registration information with the ACME server.

        :param contact: The new contact information.
        :param agreement: The new agreement contents.

        :return: The updated client's registration information as a ``dict``.

        :raises RuntimeError: If the client is not connected to a server.
        """

        if not self.is_connected:
            raise RuntimeError("Client must be connected first")

        reg_msg = messages.Registration(url=self.__reg_url)

        if contact is not None:
            reg_msg['contact'] = contact
        if agreement is not None:
            reg_msg['agreement'] = agreement

        response = await self._post_msg(reg_msg)

        return await response.json()

    async def get_challenges(self, domain):
        """
        Return a list of challenges for a given domain. By completing a
        challenge, this client will be authorized to generate certificates
        for the given domain.

        :param domain: The domain to return challenges for.

        :return: A ``dict`` containing instances of
         ``asyncme.acme.challenges.AcmeChallengeHandler`` representing the
         available challenges for the given domain. The keys of the returned
         dictionary represent the challenge type, e.g. 'http-01'.

        :raises RuntimeError: If the client is not connected to a server.
        """

        if not self.is_connected:
            raise RuntimeError("Client must be connected first")

        auth_msg = messages.NewAuthorization(identifier={
            "type": AcmeIdentifier.DNS,
            "value": domain
        })
        response = await self._post_msg(auth_msg, resp_codes=(201,))
        resp_body = await response.json()

        authz_uri = response.headers.get("location")

        challenges = {}
        for challenge_body in resp_body['challenges']:
            c = AcmeChallengeHandler(self, authz_uri, challenge_body)
            try:
                challenges[AcmeChallengeType(challenge_body['type'])] = c
            # Unsupported challenge type.
            except ValueError:
                pass

        return challenges

    async def get_cert(self, csr, not_before=None, not_after=None):
        """
        Queries the ACME server for a certificate for the given CSR.

        :param csr: Signing request for the desired certificate. Expected as
         ``bytes`` in DER format.
        :param not_before: Optional field for setting the notBefore field.
         Defaults to ``None``.
        :param not_after:  Optional field for setting the notAfter field.
         Defaults to ``None``.

        :return: ``bytes`` containing the new certificate, if the client is
         authorized for the domain in the ``csr``.

        :raises RuntimeError: If the client is not connected to a server.
        """

        if not self.is_connected:
            raise RuntimeError("Client must be connected first")

        encoded_csr = utils.jose_b64encode(csr)

        cert_msg = messages.NewCertificate(csr=encoded_csr)

        if not_before:
            cert_msg['notBefore'] = not_before
        if not_after:
            cert_msg['notAfter'] = not_after

        response = await self._post_msg(cert_msg, resp_codes=(201,))
        return await response.read()

    # ----------------------------------------------------------------------- #
    #   HTTP Helpers
    # ----------------------------------------------------------------------- #
    async def __get_nonce(self):
        async with self.__http_session.head(self.__acme_url) as response:
            return response.headers.get('Replay-Nonce')

    async def _post_msg(self, msg, *, resp_codes=(202,)):

        if not isinstance(msg, messages.AcmeResource):
            raise ValueError("Given 'msg' is not an instance of "
                             "{}".format(messages.AcmeResource))

        jws = msg.to_jws(self.priv_key, await self.__get_nonce())

        # Determine the URL, either via directory or included URL attribute.
        if isinstance(msg, messages.ACMEResourceWithURL):
            url = msg.url
        else:
            url = self.__directory[msg.resource_type]

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #
        LOG.info("Sending POST (JWS) to {}".format(url))
        LOG.debug("JWS Contents: {}".format(jws))
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

        json_types = ("application/json", "application/problem+json")
        async with self.__http_session.post(url, data=jws) as response:
            resp = response
            resp_code = response.status
            resp_headers = response.headers
            if resp_headers.get("content-type") in json_types:
                resp_body = await response.json()
            else:
                resp_body = await response.text()

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #
        LOG.info("Response {} from {}".format(resp_code, url))
        LOG.debug("Response Headers: {}".format(resp_headers))
        LOG.debug("Response Body: {}".format(resp_body))
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

        assert resp_code in resp_codes, \
            "Response {} not in expected response " \
            "codes {}".format(resp_code, resp_codes)

        return resp

    async def _get_msg(self, url):

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #
        LOG.info("Sending GET to {}".format(url))
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

        async with self.__http_session.get(url) as response:
            resp = response
            resp_code = response.status
            resp_body = await response.json()
            resp_headers = response.headers

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #
        LOG.info("Response {} from {}".format(resp_code, url))
        LOG.debug("Response Headers: {}".format(resp_headers))
        LOG.debug("Response Body: {}".format(resp_body))
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

        return resp
