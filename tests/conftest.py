
from arroyo import crypto

import pytest


# --------------------------------------------------------------------------- #


@pytest.fixture
def private_key():
    return crypto.PrivateKey.generate(crypto.KeyAlgorithmType.RSA)
