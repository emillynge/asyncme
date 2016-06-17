from enum import Enum

from asyncme import utils
from asyncme.acme import messages


# --------------------------------------------------------------------------- #


_CHALLENGE_HANDLERS = {}


# --------------------------------------------------------------------------- #


class AcmeChallengeType(str, Enum):
    DNS_01 = "dns-01",
    HTTP_01 = "http-01",
    TSL_SNI_01 = "tls-sni-01"


def register_challenge_handler(handler_cls):
    """
    Registers a new AcmeChallengeHandler for performing a challenge to
    satisfy an ACME authorization request.

    You can create your own handlers by subclassing `AcmeChallengeHandler`
    and then registering it via this function.

    :param handler_cls: The new handler to register.
    :raises ValueError: If the given handler class is invalid.
    """
    if not issubclass(handler_cls, AcmeChallengeHandler):
        raise ValueError("Given handler to register must be a subclass of "
                         "{}".format(AcmeChallengeHandler))

    if not handler_cls.type:
        raise ValueError("Given handler to register must have a challenge "
                         "type set on its `type` class attribute")

    try:
        handler_type = AcmeChallengeType(handler_cls.type)
    except ValueError:
        raise ValueError("Given handler to register has an invalid handler "
                         "type: {}".format(handler_cls.type))

    _CHALLENGE_HANDLERS[handler_type] = handler_cls


def get_challenge_handler(handler_type):

    try:
        handler_type = AcmeChallengeType(handler_type)
    except ValueError:
        raise ValueError("Invalid challenge handler type")

    return _CHALLENGE_HANDLERS.get(handler_type)


# --------------------------------------------------------------------------- #


class AcmeChallengeHandler:

    type = None

    def __new__(cls, client, authz_uri, contents):

        if cls is AcmeChallengeHandler:
            try:
                handler_type = AcmeChallengeType(contents['type'])
                actual_cls = get_challenge_handler(handler_type)
                if actual_cls:
                    return actual_cls.__new__(actual_cls, client,
                                              authz_uri, contents)
            except (ValueError, KeyError):
                pass

        return super().__new__(cls)

    def __init__(self, client, authz_uri, contents):

        self.__client = client
        self.__authz_uri = authz_uri

        self.challenge_info = messages.Challenge(url=contents['uri'],
                                                 **contents)

    @property
    def key_authorization(self):
        thumbprint = utils.jose_b64encode(self.__client.priv_key.jwk_thumbprint)
        return "{}.{}".format(self.challenge_info['token'], thumbprint)

    @property
    def loop(self):
        return self.__client._loop

    async def get_status(self):
        response = await self.__client._get_msg(self.challenge_info.url)
        resp_body = await response.json()
        return resp_body['status']

    async def get_authz(self):
        """
        Returns the Authorization resource which corresponds to this challenge.

        :return: A dictionary containing the Authorization resource contents.
        """
        response = await self.__client._get_msg(self.__authz_uri)
        return await response.json()

    async def perform(self, *args, **kwargs):
        raise NotImplementedError("This type of challenge is not implemented, "
                                  "you must perform the steps manually or "
                                  "register an AcmeChallenge subclass.")

    async def answer(self):
        self.challenge_info['keyAuthorization'] = self.key_authorization
        await self.__client._post_msg(self.challenge_info)
