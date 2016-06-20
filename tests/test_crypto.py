
import os
import tempfile
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import pytest

from asyncme import crypto


# --------------------------------------------------------------------------- #


RSA_KEY_SIZE = 2048

RSA_PUBLIC_JWK_KEYS = ['kty', 'e', 'n']
RSA_PRIVATE_JWK_KEYS = RSA_PUBLIC_JWK_KEYS + ['p', 'qi', 'd', 'dp', 'q', 'dq']


# --------------------------------------------------------------------------- #


@pytest.fixture
def rsa_private_key(request):

    # Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )

    return private_key


@pytest.fixture
def rsa_public_key(request, rsa_private_key):
    return rsa_private_key.public_key()


@pytest.fixture
def rsa_private_key_PEM_file(request, rsa_private_key):

    # Encode private key as PEM
    pem = rsa_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Write PEM key to a temporary file
    if isinstance(pem, str):
        pem = pem.encode()

    tmp = tempfile.NamedTemporaryFile(delete=False)
    with tmp as f:
        f.write(pem)

    def finalizer():
        os.remove(tmp.name)
    request.addfinalizer(finalizer)

    return tmp.name


@pytest.fixture
def rsa_public_key_PEM_file(request, rsa_public_key):

    # Encode public key as PEM
    pem = rsa_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Write PEM key to a temporary file
    if isinstance(pem, str):
        pem = pem.encode()

    tmp = tempfile.NamedTemporaryFile(delete=False)
    with tmp as f:
        f.write(pem)

    def finalizer():
        os.remove(tmp.name)
    request.addfinalizer(finalizer)

    return tmp.name


@pytest.fixture
def random_data_file(request):

    tmp = tempfile.NamedTemporaryFile(delete=False)

    with open("/dev/urandom", "rb") as in_file:
        with tmp as out_file:
            out_file.write(in_file.read(100))

    def finalizer():
        os.remove(tmp.name)

    request.addfinalizer(finalizer)

    return tmp.name


# --------------------------------------------------------------------------- #

# Generic Key Tests


def test_cannot_instantiate_asymmetric_directly(rsa_public_key):

    with pytest.raises(RuntimeError):
        crypto.AsymmetricKey(
            key=rsa_public_key,
            key_alg=crypto.KeyAlgorithm.RSA,
            key_type=crypto.KeyType.PUBLIC
        )


def test_invalid_pem_format(random_data_file):

    with pytest.raises(ValueError):
        crypto.AsymmetricKey.from_pem_file(
            random_data_file
        )


def test_len_is_size(rsa_public_key):

    key = crypto.PublicKey(rsa_public_key)
    assert key.size == len(key)


# --------------------------------------------------------------------------- #

# RSA Key Tests


def test_rsa_private_from_PEM_file(rsa_private_key_PEM_file):

    key = crypto.AsymmetricKey.from_pem_file(
        rsa_private_key_PEM_file
    )

    assert isinstance(key, crypto.AsymmetricKey)
    assert key.algorithm == crypto.KeyAlgorithm.RSA
    assert key.size == RSA_KEY_SIZE

    assert isinstance(key, crypto.PrivateKey)
    assert key.type == crypto.KeyType.PRIVATE


def test_rsa_public_from_PEM_file(rsa_public_key_PEM_file):

    key = crypto.AsymmetricKey.from_pem_file(
        rsa_public_key_PEM_file
    )

    assert isinstance(key, crypto.AsymmetricKey)
    assert key.algorithm == crypto.KeyAlgorithm.RSA
    assert key.size == RSA_KEY_SIZE

    assert isinstance(key, crypto.PublicKey)
    assert key.type == crypto.KeyType.PUBLIC


def test_rsa_private_from_obj(rsa_private_key):

    key = crypto.PrivateKey(rsa_private_key)

    assert isinstance(key, crypto.AsymmetricKey)
    assert key.algorithm == crypto.KeyAlgorithm.RSA
    assert key.size == RSA_KEY_SIZE

    assert isinstance(key, crypto.PrivateKey)
    assert key.type == crypto.KeyType.PRIVATE


def test_rsa_private_from_public_obj(rsa_public_key):

    with pytest.raises(ValueError):
        crypto.PrivateKey(rsa_public_key)


def test_rsa_private_from_bad_obj():

    with pytest.raises(ValueError):
        crypto.PrivateKey("NotValid")


def test_rsa_public_from_obj(rsa_public_key):

    key = crypto.PublicKey(rsa_public_key)

    assert isinstance(key, crypto.AsymmetricKey)
    assert key.algorithm == crypto.KeyAlgorithm.RSA
    assert key.size == RSA_KEY_SIZE

    assert isinstance(key, crypto.PublicKey)
    assert key.type == crypto.KeyType.PUBLIC


def test_rsa_public_from_private_obj(rsa_private_key):

    key = crypto.PublicKey(rsa_private_key)

    assert isinstance(key, crypto.AsymmetricKey)
    assert key.algorithm == crypto.KeyAlgorithm.RSA
    assert key.size == RSA_KEY_SIZE

    assert isinstance(key, crypto.PublicKey)
    assert key.type == crypto.KeyType.PUBLIC


def test_rsa_public_from_bad_obj():

    with pytest.raises(ValueError):
        crypto.PublicKey("NotValid")


def test_rsa_public_jwk(rsa_public_key):

    key = crypto.PublicKey(rsa_public_key)
    jwk = key.to_jwk()

    assert isinstance(jwk, dict)
    assert all(k in RSA_PUBLIC_JWK_KEYS for k in jwk.keys())

    # JWK Thumbprint
    assert isinstance(key.jwk_thumbprint, bytes)
    assert len(key.jwk_thumbprint) * 8 == 256


def test_rsa_private_jwk(rsa_private_key):

    key = crypto.PrivateKey(rsa_private_key)
    jwk = key.to_jwk()

    assert isinstance(jwk, dict)
    assert all(k in RSA_PRIVATE_JWK_KEYS for k in jwk.keys())

    # Ensure that the Public Key's JWK is a Subset of the Private Key's JWK
    pub_jwk = set(key.public_key.to_jwk().items())
    assert pub_jwk.issubset(set(jwk.items()))

    # JWK Thumbprint
    assert isinstance(key.jwk_thumbprint, bytes)
    assert len(key.jwk_thumbprint) * 8 == 256

    # Public and Private Thumbprint should be the Same
    assert key.jwk_thumbprint == key.public_key.jwk_thumbprint


def test_rsa_private_thumbprint(rsa_private_key):

    key = crypto.PrivateKey(rsa_private_key)

    assert isinstance(key.thumbprint, bytes)
    assert len(key.thumbprint) * 8 == 256

    # `fingerprint` is a synonym to thumbprint
    assert key.thumbprint == key.fingerprint

    # Public and Private Thumbprint should be the Same
    assert key.thumbprint == key.public_key.thumbprint

    # Verify Hash Contents
    pub_bytes = key.public_key._key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )

    if isinstance(pub_bytes, str):
        pub_bytes = pub_bytes.encode()

    hash = hashlib.sha256(pub_bytes).digest()
    assert key.thumbprint == hash


def test_rsa_public_thumbprint(rsa_public_key):

    key = crypto.PublicKey(rsa_public_key)

    assert isinstance(key.thumbprint, bytes)
    assert len(key.thumbprint) * 8 == 256

    # `fingerprint` is a synonym to thumbprint
    assert key.thumbprint == key.fingerprint

    # Verify Hash Contents
    pub_bytes = rsa_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1
    )

    if isinstance(pub_bytes, str):
        pub_bytes = pub_bytes.encode()

    hash = hashlib.sha256(pub_bytes).digest()
    assert key.thumbprint == hash
