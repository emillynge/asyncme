
import logging
from enum import Enum

from jwcrypto.jwk import JWK as CryptoJWK
from jwcrypto.jws import JWS as CryptoJWS

from asyncme import utils

# --------------------------------------------------------------------------- #


LOG = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #


class ResourceType(str, Enum):
    NEW_REG = "new-reg",
    REG = "reg",
    NEW_AUTHZ = "new-authz",
    AUTHZ = "authz",
    NEW_CERT = "new-cert",
    REVOKE_CERT = "revoke-cert"
    CHALLENGE = "challenge"


class AcmeResource(dict):

    resource_type = None                # type: ResourceType
    resource_fields = ()

    def __init__(self, **kwargs):

        for key in kwargs:
            if key not in self.resource_fields:
                raise KeyError("This resource only supports the fields "
                               "{}".format(self.resource_fields))

        super().__init__(**kwargs)

        # Set the resource value
        try:
            dict.__setitem__(self, "resource", self.resource_type.value)
        except AttributeError:
            pass

    def __setitem__(self, key, value):
        if key not in self.resource_fields:
            raise KeyError("This resource only supports the fields {}".format(
                self.resource_fields
            ))
        return dict.__setitem__(self, key, value)

    def to_jws(self, priv_key, nonce, *, alg='RS256', compact=False):
        """
        Convert this ACME resource to a signed JWS, capable of sending to
        the ACME server.

        :param priv_key: Private key used to sign the JWS.
        :param nonce: Nonce used in the JWS to mitigate replay.
        :param alg: Algorithm used for signing the JWS, defaults to `RS256`.
        :param compact: Return a compacted JWS object (fully encoded separated
         by dots). Defaults to `False`.

        :return: The JWS object.
        """
        jwk_priv = priv_key.to_jwk()
        jwk_pub = priv_key.public_key.to_jwk()

        protected = utils.dumps({
            'jwk': jwk_pub,
            'nonce': nonce,
            'alg': alg
        })

        jwk_obj = CryptoJWK(**jwk_priv)

        jws_obj = CryptoJWS(utils.dumps(self))
        jws_obj.add_signature(key=jwk_obj, protected=protected)

        return jws_obj.serialize(compact=compact)


class ACMEResourceWithURL(AcmeResource):

    def __init__(self, url, **kwargs):
        self.url = url
        super().__init__(**kwargs)


class NewRegistration(AcmeResource):

    resource_type = ResourceType.NEW_REG
    resource_fields = ("contact", "agreement")


class Registration(ACMEResourceWithURL):

    resource_type = ResourceType.REG
    resource_fields = ("key", "contact", "agreement", "authorizations",
                       "certificates")


class NewAuthorization(AcmeResource):

    resource_type = ResourceType.NEW_AUTHZ
    resource_fields = ("identifier", )


class Challenge(ACMEResourceWithURL):

    resource_type = ResourceType.CHALLENGE
    resource_fields = ("type", "token", "keyAuthorization", "status", "uri")


class NewCertificate(AcmeResource):

    resource_type = ResourceType.NEW_CERT
    resource_fields = ("csr", "notBefore", "notAfter")
