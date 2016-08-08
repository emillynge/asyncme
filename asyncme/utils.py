"""
Utilities for interacting with JOSE objects and the ACME protocol.
"""

# --------------------------------------------------------------------------- #


import json


# --------------------------------------------------------------------------- #


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
