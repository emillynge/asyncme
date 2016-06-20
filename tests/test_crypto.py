
import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import pytest

from asyncme import crypto


# --------------------------------------------------------------------------- #


RSA_KEY_SIZE = 2048


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
        foramt=serialization.PublicFormat.SubjectPublicKeyInfo
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


# --------------------------------------------------------------------------- #


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
