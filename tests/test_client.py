
import pytest


# --------------------------------------------------------------------------- #

# Asyncme Client Tests

from asyncme.acme.challenges import AcmeChallengeType
from asyncme.acme.client import AcmeClient


# --------------------------------------------------------------------------- #


ACME_URL = "https://acme-staging.api.letsencrypt.org/directory"


# --------------------------------------------------------------------------- #


@pytest.fixture
def acme_client(event_loop, private_key):
    return AcmeClient(private_key, loop=event_loop)


# --------------------------------------------------------------------------- #


def test_client_bad_private_key():

    with pytest.raises(ValueError):
        AcmeClient("NotAValidKey")


def test_client_prevent_changing_of_key(acme_client):

    with pytest.raises(AttributeError):
        acme_client.priv_key = None


def test_client_url_is_none_before_connect(acme_client):

    assert acme_client.url is None


@pytest.mark.asyncio
async def test_client_connect(event_loop, private_key):

    # Test Connecting with Fresh Private Key
    client = AcmeClient(private_key, loop=event_loop)
    reg_info = await client.connect(ACME_URL)

    # Test that Connect Returns Registration Info
    assert isinstance(reg_info, dict)
    assert len(reg_info) > 0

    # Test Connecting with a Previously Registered Key
    client = AcmeClient(private_key, loop=event_loop)
    await client.connect(ACME_URL)


@pytest.mark.asyncio
async def test_client_connect_bad_acme_url(acme_client):

    with pytest.raises(ValueError):
        await acme_client.connect("http://www.google.com")


@pytest.mark.asyncio
async def test_client_url_is_set_after_connect(acme_client):

    await acme_client.connect(ACME_URL)
    assert acme_client.url == ACME_URL


@pytest.mark.asyncio
async def test_client_prevents_double_connect(acme_client):

    await acme_client.connect(ACME_URL)
    with pytest.raises(RuntimeError):
        await acme_client.connect(ACME_URL)


@pytest.mark.asyncio
async def test_client_connect_to_nonstring_url(acme_client):

    with pytest.raises(ValueError):
        await acme_client.connect(12345)


@pytest.mark.asyncio
async def test_client_connect_to_non_compliant_api(acme_client):

    with pytest.raises(ValueError) as excinfo:
        await acme_client.connect("https://api.github.com")
        assert "did not present proper ACME functions" in str(excinfo.value)


@pytest.mark.asyncio
async def test_client_get_reg_before_connect(acme_client):

    with pytest.raises(RuntimeError):
        await acme_client.get_reg()


@pytest.mark.asyncio
async def test_client_get_tos_before_connect(acme_client):

    with pytest.raises(RuntimeError):
        await acme_client.get_tos()


@pytest.mark.asyncio
async def test_client_get_tos(acme_client):

    await acme_client.connect(ACME_URL)
    tos = await acme_client.get_tos()

    assert isinstance(tos, str) or tos is None


@pytest.mark.asyncio
async def test_client_update_reg_before_connect(acme_client):

    with pytest.raises(RuntimeError):
        await acme_client.update_reg()


@pytest.mark.asyncio
async def test_client_update_reg(acme_client):

    await acme_client.connect(ACME_URL)
    response = await acme_client.update_reg(contact=[], agreement="")

    assert isinstance(response, dict)
    assert len(response) > 0


@pytest.mark.asyncio
async def test_client_get_challenges_before_connect(acme_client):

    with pytest.raises(RuntimeError):
        await acme_client.get_challenges(domain="www.google.com")


@pytest.mark.asyncio
async def test_client_get_challenges(acme_client):

    await acme_client.connect(ACME_URL)

    # Make sure we've agreed to any terms first.
    tos = await acme_client.get_tos()
    await acme_client.update_reg(agreement=tos)

    challenges = await acme_client.get_challenges("www.arroyonetworks.com")

    assert isinstance(challenges, dict)
    assert all(k in AcmeChallengeType for k in challenges)


@pytest.mark.asyncio
async def test_client_get_cert_before_connect(acme_client):

    with pytest.raises(RuntimeError):
        await acme_client.get_cert(csr=b'\x00')
