
import json
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

    def __init__(self, priv_key, *, loop=None):

        # Instance Attributes

        # priv_key
        #   Type Check
        if not isinstance(priv_key, crypto.PrivateKey):
            raise ValueError("'priv_key' must be an instance of {}".format(
                crypto.PrivateKey
            ))
        self.__priv_key = priv_key

        self._loop = loop or asyncio.get_event_loop()
        self.__http_session = aiohttp.ClientSession(loop=self._loop)

        # ACME Server Attributes
        self.__connected = False
        self.__acme_url = None
        self.__directory = None
        self.__reg_url = None

    def __del__(self):
        if self and self.__http_session:
            self.__http_session.close()

    @property
    def priv_key(self):
        return self.__priv_key

    @priv_key.setter
    def priv_key(self, value):
        raise AttributeError("Cannot change Private Key, create a new client "
                             "instance instead.")

    @property
    def url(self):
        return self.__acme_url

    @property
    def is_connected(self):
        return self.__connected

    async def connect(self, url):
        """
        Connect to an ACME server.

        The client's key will automatically be registered with the remote
        server.

        :param url: The URL of the directory for the ACME server to connect to.
        :raises ValueError: If the given URL is unavailable or is not a valid
         ACME directory.
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

        if not self.is_connected:
            raise RuntimeError("Client must be connected first")

        reg_msg = messages.Registration(url=self.__reg_url)

        if contact:
            reg_msg['contact'] = contact
        if agreement:
            reg_msg['agreement'] = agreement

        response = await self._post_msg(reg_msg)

        return await response.json()

    async def get_challenges(self, domain):

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
        LOG.debug("Sending\n{}\nto {}".format(
            json.dumps(json.loads(jws), indent=4),
            url
        ))
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

        async with self.__http_session.post(url, data=jws) as response:
            resp = response
            resp_code = response.status
            resp_headers = response.headers
            if resp_headers.get("content-type") == "application/json":
                resp_body = await response.json()
            else:
                resp_body = await response.text()

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #
        LOG.debug("Response from {}:\nHEADERS {}\nSTATUS {}\n{}".format(
            url,
            resp_headers,
            resp_code,
            json.dumps(resp_body, indent=4)
        ))
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

        assert resp_code in resp_codes, \
            "Response {} not in expected response " \
            "codes {}".format(resp_code, resp_codes)

        return resp

    async def _get_msg(self, url):
        async with self.__http_session.get(url) as response:
            resp = response
            resp_code = response.status
            resp_body = await response.json()
            resp_headers = response.headers

        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #
        LOG.debug("Response from {}:\nHEADERS {}\nSTATUS {}\n{}".format(
            url,
            resp_headers,
            resp_code,
            json.dumps(resp_body, indent=4)
        ))
        # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #

        return resp
