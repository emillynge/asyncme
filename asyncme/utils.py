"""
Utilities for interacting with JOSE objects and the ACME protocol.
"""

# --------------------------------------------------------------------------- #


import base64
import json


# --------------------------------------------------------------------------- #


def jose_b64encode(s):
    """
    Base64 encodes the given data via:
        - URL safe encoding
        - Stripped padding

    :param s: Data to encode.
    :return: Base64 encoded data as a string.
    """
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64encode(s).rstrip(b'=').decode()


def jose_b64decode(s):
    """
    Base64 decodes the given data assuming data is:
        - URL safe encoded
        - May have padding stripped

    :param s: Data to decode from Base64.
    :return: Decoded data.
    """
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64decode(s + b'=' * (4 - (len(s) % 4)))


class ExtendedEncoder(json.JSONEncoder):
    """
    Extended JSON encoder for serializing to JOSE specifications.

    Specifically this encoder:
        - Decodes bytes to their UTF-8 string representation.
    """
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode()
        return super().default(o)


def dumps(obj):
    """
    Serialize the given object using the modified ExtendedEncoder.

    Keys are automatically sorted, and the JSON object is compacted without
    whitespace.

    :param obj: Object to serialize.
    :return: String representing the JSON serialized object.
    """
    return json.dumps(
        obj,
        cls=ExtendedEncoder,
        sort_keys=True,
        separators=(',', ':')
    )

loads = json.loads
