
import os
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import pytest


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
def valid_private_key(rsa_private_key):
    from asyncme.crypto import PrivateKey
    return PrivateKey(rsa_private_key)


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
