# --------------------------------------------------------------------------- #


from math import ceil
from enum import Enum

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat import backends

from asyncme import utils


# --------------------------------------------------------------------------- #


class KeyAlgorithm(str, Enum):
    RSA = "RSA"


class KeyType(str, Enum):
    PRIVATE = "PRIVATE"
    PUBLIC = "PUBLIC"


def _prepare_key_num(num):
    # NOTE: --
    # Some implementations will but a leading null byte in front of key
    # numbers to remove the ambiguity with their sign, however JOSE/JWK
    # requires that there be no null bytes.
    #
    # While this does not affect
    # signing operations, it will cause the fingerprint/thumbprint to
    # be wrong.

    if isinstance(num, int):
        num = num.to_bytes(ceil(num.bit_length() / 8), "big")

    if isinstance(num, bytes):
        num = utils.jose_b64encode(num)

    return num


class AsymmetricKey:

    @staticmethod
    def from_pem_file(filename, password=None):
        with open(filename, "rb") as keyfile:
            keybytes = keyfile.read()
        if b'public' in keybytes.splitlines()[0].lower():
            key = serialization.load_pem_public_key(
                    keybytes,
                    backend=backends.default_backend()
            )
            return PublicKey(key)
        elif b'private' in keybytes.splitlines()[0].lower():
            key = serialization.load_pem_private_key(
                    keybytes,
                    password,
                    backend=backends.default_backend()
            )
            return PrivateKey(key)
        else:
            raise ValueError("Key does not appear to be valid PEM format.")

    def __init__(self, key, *, key_alg, key_type):
        self._key = key
        self._alg = key_alg
        self._type = key_type

    @property
    def algorithm(self):
        return KeyAlgorithm(self._alg)

    @property
    def type(self):
        return KeyType(self._type)

    @property
    def size(self):
        return self._key.key_size

    @property
    def thumbprint(self):
        raise NotImplementedError("Must be implemented by subclass")

    @property
    def fingerprint(self):
        return self.thumbprint

    @property
    def jwk_thumbprint(self):
        raise NotImplementedError("Must be implemented by subclass")

    def __len__(self):
        return self.size

    def to_jwk(self):
        return {
            "kty": KeyAlgorithm(self.algorithm).upper()
        }


class PublicKey(AsymmetricKey):

    def __init__(self, key):
        super().__init__(
            key=key,
            key_alg=KeyAlgorithm.RSA,
            key_type=KeyType.PUBLIC
        )

    @property
    def thumbprint(self):

        pub_bytes = self._key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1
        )

        pub_hash = hashes.Hash(hashes.SHA256(), backends.default_backend())
        pub_hash.update(pub_bytes)

        return pub_hash.finalize()

    @property
    def jwk_thumbprint(self):

        jwk = self.to_jwk()
        jwk_string = utils.dumps(jwk)

        jwk_hash = hashes.Hash(hashes.SHA256(), backends.default_backend())
        jwk_hash.update(jwk_string.encode())

        return jwk_hash.finalize()

    def to_jwk(self):
        jwk = super().to_jwk()
        jwk['n'] = _prepare_key_num(self._key.public_numbers().n)
        jwk['e'] = _prepare_key_num(self._key.public_numbers().e)

        return jwk


class PrivateKey(AsymmetricKey):

    def __init__(self, key):
        super().__init__(
            key=key,
            key_alg=KeyAlgorithm.RSA,
            key_type=KeyType.PRIVATE
        )

        self._public_key = PublicKey(key.public_key())

    @property
    def thumbprint(self):
        return self.public_key.thumbprint

    @property
    def jwk_thumbprint(self):
        return self.public_key.jwk_thumbprint

    @property
    def public_key(self):
        return self._public_key

    def to_jwk(self):
        jwk = self.public_key.to_jwk()
        jwk['d'] = _prepare_key_num(self._key.private_numbers().d)
        jwk['p'] = _prepare_key_num(self._key.private_numbers().p)
        jwk['q'] = _prepare_key_num(self._key.private_numbers().q)
        jwk['dp'] = _prepare_key_num(self._key.private_numbers().dmp1)
        jwk['dq'] = _prepare_key_num(self._key.private_numbers().dmq1)
        jwk['qi'] = _prepare_key_num(self._key.private_numbers().iqmp)

        return jwk
