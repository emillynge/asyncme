# --------------------------------------------------------------------------- #


import inspect

from acme import jose, messages
from arroyo import crypto

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import pytest


# --------------------------------------------------------------------------- #

# Test Fixtures and Globals

DIRECTORY_URL = 'https://acme-staging.api.letsencrypt.org/directory'
MIN_BITS = 2048
DOMAIN = "seglberg.arroyo.io"


@pytest.fixture
def acme_jwk():
    return jose.JWKRSA(key=rsa.generate_private_key(
        public_exponent=65537,
        key_size=MIN_BITS,
        backend=default_backend())
    )


@pytest.fixture
def exec_client(event_loop, acme_jwk):
    from acme.client import Client
    return ExecutorClient(Client(DIRECTORY_URL, acme_jwk), loop=event_loop)


@pytest.fixture(scope="session", params=(
        ("RSA", 256 * 8),
        ("RSA", 384 * 8),
        ("RSA", 512 * 8),
        ("ECDSA", 256),
        ("ECDSA", 384),
        ("ECDSA", 521)
))
def private_key(request):
    return crypto.PrivateKey.generate(request.param[0], size=request.param[1])


# --------------------------------------------------------------------------- #

# Tests for ExecutorClient

from asyncme.client import ExecutorClient


@pytest.mark.asyncio
async def test_executor_client_connect(event_loop, acme_jwk):
    """Tests that the connect method is a coroutine that produces a
    subclass of ``acme.client.Client``"""

    assert inspect.iscoroutinefunction(ExecutorClient.connect)

    client = await ExecutorClient.connect(
        DIRECTORY_URL, acme_jwk, loop=event_loop
    )

    assert isinstance(client, ExecutorClient)


def test_executor_client_non_existing_attr(exec_client):

    with pytest.raises(AttributeError):
        _ = exec_client.this_does_not_exist


def test_executor_client_non_callable_attr(exec_client):

    net = exec_client.net
    assert net is exec_client._client.net


def test_executor_client_loop_attr(event_loop, exec_client):

    assert exec_client.loop is event_loop


@pytest.mark.asyncio
async def test_executor_client_example(exec_client):
    """Tests the executor subclass by running through the ACME example
    steps."""

    # (1) Register
    regr = await exec_client.register()
    assert isinstance(regr, messages.RegistrationResource)

    # (2) Agree to Terms
    regr = await exec_client.agree_to_tos(regr)
    assert isinstance(regr, messages.RegistrationResource)

    # (3) Get Challenges for Domain
    authzr = await exec_client.request_domain_challenges(
        DOMAIN, new_authzr_uri=regr.new_authzr_uri
    )
    assert isinstance(authzr, messages.AuthorizationResource)

    # (4) Poll
    authzr, _ = await exec_client.poll(authzr)
    assert isinstance(authzr, messages.AuthorizationResource)


# --------------------------------------------------------------------------- #

# Tests for AsyncmeClient

from asyncme.client import AsyncmeClient


@pytest.mark.asyncio
async def test_asyncme_client_connect(event_loop, private_key):

    # xfail because not all key types are currently supported upstream
    # in the ACME client (ECDSA)

    assert inspect.iscoroutinefunction(AsyncmeClient.connect)

    try:
        client = await AsyncmeClient.connect(
            DIRECTORY_URL, private_key, loop=event_loop
        )
    except AttributeError as e:
        if "object has no attribute 'kty'" in str(e):
            pytest.xfail("ACME Client does not support ECDSA keys yet")
        raise e
    except RuntimeError as e:
        if "in JWS header is not supported" in str(e):
            pytest.xfail("Boulder does not support this key + size")
        raise e

    assert isinstance(client, AsyncmeClient)


# @pytest.mark.asyncio
# async def test_asyncme_client_connect_invalid_dir(event_loop):
#     private_key = crypto.PrivateKey.generate("RSA")
#
#     with pytest.raises(ValueError):
#         await AsyncmeClient.connect(
#             "http://api.github.com/events", private_key, loop=event_loop
#         )


@pytest.mark.asyncio
async def test_asyncme_double_connect(event_loop):
    """Ensure that the client is capable of connected with a key that is
    already registered."""
    private_key = crypto.PrivateKey.generate("RSA")

    client1 = await AsyncmeClient.connect(
        DIRECTORY_URL, private_key, loop=event_loop
    )

    client2 = await AsyncmeClient.connect(
        DIRECTORY_URL, private_key, loop=event_loop
    )

    assert client1._regr == client2._regr


@pytest.mark.asyncio
async def test_asyncme_unsupported_rsa_size(event_loop):

    private_key = crypto.PrivateKey.generate("RSA", size=1024)

    with pytest.raises(ValueError):
        await AsyncmeClient.connect(
            DIRECTORY_URL, private_key, loop=event_loop
        )
