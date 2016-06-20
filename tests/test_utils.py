
import json

from asyncme import utils

import pytest


# --------------------------------------------------------------------------- #


RSA_PUBLIC_JWK_KEYS = ['kty', 'e', 'n']
RSA_PRIVATE_JWK_KEYS = RSA_PUBLIC_JWK_KEYS + ['p', 'qi', 'd', 'dp', 'q', 'dq']


# --------------------------------------------------------------------------- #

# Utils Tests

def test_jose_encode_str():
    """Ensure that a `str` is encoded to base64 to JOSE specification"""
    data = "aa?a"
    encoded = utils.jose_b64encode(data)

    assert encoded.find('/') == -1
    assert encoded.find('+') == -1
    assert encoded.find('=') == -1


def test_jose_encoded_bytes():
    """Ensure that 'bytes` is encoded to base64 to JOSE specification"""
    data = b'\x03\xE0\x3F\x00'
    encoded = utils.jose_b64encode(data)

    assert encoded.find('/') == -1
    assert encoded.find('+') == -1
    assert encoded.find('=') == -1


def test_jose_decode_str():
    """Ensure that a base64 `str` encoded to JOSE specification is decoded"""
    data = "YWE_YQ"
    decoded = utils.jose_b64decode(data)

    assert decoded == b'aa?a'


def test_jose_decode_bytes():
    """Ensure that a base64 set of 'bytes' encoded to JOSE spec. is decoded"""
    data = b'A-A_AA'
    decoded = utils.jose_b64decode(data)

    assert decoded == b'\x03\xE0\x3F\x00'


def test_custom_json_encoder():

    data = {'bytes': b'bytes'}
    json_str = json.dumps(data, cls=utils.ExtendedEncoder)

    assert json_str == '{"bytes": "bytes"}'


def test_custom_json_encoder_still_raises_on_unexpected_value():

    with pytest.raises(TypeError):
        json.dumps(str, cls=utils.ExtendedEncoder)


def test_custom_dumps():

    data = {'bytes': b'bytes', "int": 1}
    json_str = utils.dumps(data)

    # `dumps` in utils is required to produce minified JSON
    assert json_str == '{"bytes":"bytes","int":1}'

def test_custom_loads():

    json_str = '{"bytes":"bytes","int":1}'
    data = utils.loads(json_str)

    assert len(data) == 2
    assert data["int"] == 1
