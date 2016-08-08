
import json

import pytest


# --------------------------------------------------------------------------- #

# ACME Messages - AcmeResource Base Class Tests

from asyncme.acme import messages


# --------------------------------------------------------------------------- #


class MyResource(messages.AcmeResource):
    resource_fields = ('test',)


class MyResourceWithURL(messages.ACMEResourceWithURL):
    resource_fields = ('test',)


def test_restricted_setitem():

    my_resource = MyResource()

    # Set Allowed Field
    my_resource['test'] = 'test'

    # Set Not Allowed Field
    with pytest.raises(KeyError):
        my_resource['no'] = 'no'


def test_restricted_setitem_on_init():

    # Set Allowed Field
    MyResource(test='test')

    # Set Not Allowed Field
    with pytest.raises(KeyError):
        MyResource(no='no')


def test_convert_to_jws(private_key):

    my_resource = MyResource()
    jws = my_resource.to_jws(private_key, 'my_random_nonce')

    # Non-compacted JWS is a valid JSONified object
    json.loads(jws)


def test_allow_url_kw_on_init_with_url_resource():

    my_resource = MyResourceWithURL(test='test', url='url')

    with pytest.raises(KeyError):
        my_resource['url'] = 'url'
