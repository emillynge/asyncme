
import json

from asyncme import utils

import pytest


# --------------------------------------------------------------------------- #

# Utils Tests


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
