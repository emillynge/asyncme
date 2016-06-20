from . import acme                                                       # noqa
from .acme.client import AcmeClient                                      # noqa
from .acme.challenges import register_challenge_handler                  # noqa

from . import crypto                                                     # noqa
from .crypto import AsymmetricKey                                        # noqa

from . import utils                                                      # noqa


# Please refrain from specifying a micro version if possible.
# --------------------------------------------------------------------------- #
VERSION = (0, 1, 'b3')
# --------------------------------------------------------------------------- #


def _get_version(version_tuple):                                                # pragma: nocover # noqa
    end = version_tuple[-1]                                                     # pragma: nocover # noqa
    if isinstance(end, str) and end.startswith(('a', 'b', 'rc')):               # pragma: nocover # noqa
        return '.'.join(map(str, version_tuple[:-1])) + version_tuple[-1]       # pragma: nocover # noqa
    return '.'.join(map(str, version_tuple))                                    # pragma: nocover # noqa

__version__ = _get_version(VERSION)

del _get_version
