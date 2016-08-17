# from . import acme                                                       # noqa
# from .acme.client import AcmeClient                                      # noqa


# Please refrain from specifying a micro version if possible.
# --------------------------------------------------------------------------- #
VERSION = (0, 2, 'rc3')
# --------------------------------------------------------------------------- #


def _get_version(vt):                                                           # pragma: nocover # noqa
    vt = tuple(map(str, vt))                                                    # pragma: nocover # noqa
    m = map(lambda v: v.startswith(('a', 'b', 'rc')), vt)                       # pragma: nocover # noqa
    try:                                                                        # pragma: nocover # noqa
        i = next(i for i, v in enumerate(m) if v)                               # pragma: nocover # noqa
    except StopIteration:                                                       # pragma: nocover # noqa
        return '.'.join(vt)                                                     # pragma: nocover # noqa
    return '.'.join(vt[:i]) + '.'.join(vt[i:])                                  # pragma: nocover # noqa

__version__ = _get_version(VERSION)

del _get_version
