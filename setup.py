#!/usr/bin/env python3

import os
import sys
from warnings import warn
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))


# --------------------------------------------------------------------------- #

# Warn if Using Unsupported Python Version. Currently only support Python 3.5+


if (sys.version_info[0] < 3 or
        (sys.version_info[0] == 3 and sys.version_info[1] < 5)):
    warn("Unsupported Version of Python Detected. Use at your Own Risk.")


# --------------------------------------------------------------------------- #

# Package Info

NAME = 'asyncme'
DESCRIPTION = 'ACME Protocol Implementation for AsyncIO'
LONG_DESCRIPTION = None
try:
    with open('README.rst') as f:
        LONG_DESCRIPTION = f.read()
except (FileNotFoundError, PermissionError):
    pass


def _get_version(version_tuple):
    end = version_tuple[-1]
    if isinstance(end, str) and end.startswith(('a', 'b', 'rc')):
        return '.'.join(map(str, version_tuple[:-1])) + version_tuple[-1]
    return '.'.join(map(str, version_tuple))

# Read the Version from __init__.py Manually by Opening the File
init = os.path.join(here, NAME, '__init__.py')
version_line = list(filter(lambda l: l.startswith('VERSION'), open(init)))[0]

VERSION = _get_version(eval(version_line.split('=')[-1]))

# --------------------------------------------------------------------------- #


upstream_url = "https://github.com/ArroyoNetworks/{}"
download_url = upstream_url + "/archive/v{}.tar.gz"


setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    author='Arroyo Networks',
    author_email='hello@arroyonetworks.com',
    maintainer='Matthew Ellison',
    maintainer_email='matt@arroyonetworks.com',
    url=upstream_url.format(NAME),
    download_url=download_url.format(NAME, VERSION),
    packages=find_packages(
        exclude=["*.tests", "*.tests.*", "tests.*", "tests"]
    ),
    include_package_data=True,
    license='MIT',
    platforms=['any'],
    install_requires=[
        'aiohttp',
        'cryptography',
        'jwcrypto',
    ],
    extras_require={
        'dns': [
            'apache-libcloud',
        ]
    },
    tests_require=[
        'pytest',
        'pytest-flake8'
    ],
    keywords=["acme", "let's encrypt", "ssl", "cert", "async", "asyncio"],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.5',
    ]
)
