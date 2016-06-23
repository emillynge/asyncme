from enum import Enum

from asyncio import BaseEventLoop

from asyncme import utils
from asyncme.acme import messages

# --------------------------------------------------------------------------- #

# Type Hints

import asyncme.acme.client


# --------------------------------------------------------------------------- #


class AcmeChallengeType(str, Enum):
    DNS_01 = "dns-01",
    HTTP_01 = "http-01",
    TLS_SNI_01 = "tls-sni-01"


class AcmeChallenge:
    """
    The AcmeChallenge class represents the parameters of an ACME authorization
    challenge, and contains all the information necessary for a handler
    to complete and response to the challenge.
    """

    def __init__(self, client: 'asyncme.acme.client.AcmeClient', authz: dict,
                 contents: dict):
        """
        Creates a new ACMEChallenge object/

        :param client: The client which created the challenge.
        :param authz: The authz information containing the challenge.
        :param contents: This challenge's contents.
        """

        self.__client = client
        self.__loop = self.__client._loop
        self.__authz = authz

        self.challenge_info = messages.Challenge(url=contents['uri'],
                                                 **contents)

    @property
    def fqdn(self) -> str:
        """
        :return: The fully qualified name of the domain being authorized by
         this challenge.
        """
        fqdn = self.__authz['identifier']['value']
        if not fqdn.endswith("."):
            fqdn += "."
        return fqdn

    @property
    def key_authorization(self) -> str:
        """
        :return: The `keyAuthorization` of the challenge.
        """
        thumbprint = utils.jose_b64encode(
            self.__client.priv_key.jwk_thumbprint
        )
        return "{}.{}".format(self.challenge_info['token'], thumbprint)

    @property
    def type(self) -> AcmeChallengeType:
        """
        :return: This challenge's type.
        """
        return AcmeChallengeType(self.challenge_info['type'])

    @property
    def url(self) -> str:
        """
        :return: The URL of this challenge on the ACME server.
        """
        return self.challenge_info.url

    async def answer(self) -> None:
        """
        Answers this challenge, thereby allowing to remote ACME server to check
        for the proper answer in an attempt to validate the authorization
        request.
        """
        self.challenge_info['keyAuthorization'] = self.key_authorization
        await self.__client._post_msg(self.challenge_info)

    async def get_status(self) -> str:
        """
        Gets the current status of this ACME challenge (authorization status).

        Authorization status may be:
        - unknown
        - pending
        - processing
        - valid
        - invalid
        - revoked

        XXX: Might be worth making an Enum for these as well, since we will
        XXX: want to eventually have more in-depth checking of authorization
        XXX: statuses.

        :return: The current status of this ACME challenge, according to the
         remote server.
        """
        response = await self.__client._get_msg(self.challenge_info.url)
        resp_body = await response.json()
        return resp_body['status']

    def get_client_loop(self) -> BaseEventLoop:
        """
        Get's the asynchronous loop instance used by the ``AcmeClient``
        which created this challenge.

        :return: The asynchronous loop used by the client.
        """
        return self.__loop
