from . import acme
from .acme.client import AcmeClient

from . import crypto
from .crypto import AsymmetricKey

from . import utils


# Please refrain from specifying a micro version if possible.
# --------------------------------------------------------------------------- #
VERSION = (0, 1, 'b1')
# --------------------------------------------------------------------------- #


def _get_version(version_tuple):                                                # pragma: nocover # noqa
    end = version_tuple[-1]                                                     # pragma: nocover # noqa
    if isinstance(end, str) and end.startswith(('a', 'b', 'rc')):               # pragma: nocover # noqa
        return '.'.join(map(str, version_tuple[:-1])) + version_tuple[-1]       # pragma: nocover # noqa
    return '.'.join(map(str, version_tuple))                                    # pragma: nocover # noqa

__version__ = _get_version(VERSION)

del _get_version
