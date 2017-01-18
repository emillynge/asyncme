#!/usr/bin/env python3

import sys
from warnings import warn
from setuptools import setup, find_packages

import versioneer


# --------------------------------------------------------------------------- #

# Warn if Using Unsupported Python Version. Currently only support Python 3.5+


if (sys.version_info[0] < 3 or
        (sys.version_info[0] == 3 and sys.version_info[1] < 5)):
    warn("Unsupported Version of Python Detected. Use at your Own Risk.")


# --------------------------------------------------------------------------- #

# Package Info

NAME = 'asyncme'
DESCRIPTION = 'Async ACME Protocol Client for AsyncIO'
LONG_DESCRIPTION = None
try:
    with open('README.rst') as f:
        LONG_DESCRIPTION = f.read()
except (FileNotFoundError, PermissionError):
    pass


# --------------------------------------------------------------------------- #

VERSION = versioneer.get_version()

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
    license='Apache',
    platforms=['any'],
    setup_requires=[
        'pytest-runner',
    ],
    install_requires=[
        'acme>=0.9',
        'arroyo-crypto>=1.0',
        'dnspython'
    ],
    extras_require={
        'libcloud': ["apache-libcloud>=1.0.0"],
    },
    tests_require=[
        'pytest',
        'pytest-flake8',
        'pytest-asyncio',
        'pytest-cov',
        'pytest-timeout'
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
