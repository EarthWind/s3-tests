import boto3
import botocore.session
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
from nose.tools import eq_ as eq
from nose.plugins.attrib import attr
from nose.plugins.skip import SkipTest
import isodate
import email.utils
import datetime
import threading
import re
import pytz
from collections import OrderedDict
import requests
import json
import base64
import hmac
import hashlib
import xml.etree.ElementTree as ET
import time
import operator
import nose
import os
import string
import random
import socket
import ssl
from collections import namedtuple

from email.header import decode_header

from .utils import assert_raises
from .utils import generate_random
from .utils import _get_status_and_error_code
from .utils import _get_status

from .policy import Policy, Statement, make_json_policy

from . import (
    get_client,
    get_prefix,
    get_unauthenticated_client,
    get_bad_auth_client,
    get_v2_client,
    get_new_bucket,
    get_new_bucket_name,
    get_new_bucket_resource,
    get_config_is_secure,
    get_config_host,
    get_config_port,
    get_config_endpoint,
    get_main_aws_access_key,
    get_main_aws_secret_key,
    get_main_display_name,
    get_main_user_id,
    get_main_email,
    get_main_api_name,
    get_alt_aws_access_key,
    get_alt_aws_secret_key,
    get_alt_display_name,
    get_alt_user_id,
    get_alt_email,
    get_alt_client,
    get_tenant_client,
    get_tenant_iam_client,
    get_tenant_user_id,
    get_buckets_list,
    get_objects_list,
    get_main_kms_keyid,
    get_secondary_kms_keyid,
    get_svc_client,
    nuke_prefixed_buckets,
    )

def _bucket_is_empty(bucket):
    is_empty = True
    for obj in bucket.objects.all():
        is_empty = False
        break
    return is_empty

def _create_objects(bucket=None, bucket_name=None, keys=[]):
    """
    Populate a (specified or new) bucket with objects with
    specified names (and contents identical to their names).
    """
    if bucket_name is None:
        bucket_name = get_new_bucket_name()
    if bucket is None:
        bucket = get_new_bucket_resource(name=bucket_name)

    for key in keys:
        obj = bucket.put_object(Body=key, Key=key)

    return bucket_name

def _get_body(response):
    body = response['Body']
    got = body.read()
    if type(got) is bytes:
        got = got.decode()
    return got

def check_bad_bucket_name(bucket_name):
    """
    Attempt to create a bucket with a specified name, and confirm
    that the request fails because of an invalid bucket name.
    """
    client = get_client()
    e = assert_raises(ClientError, client.create_bucket, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# AWS does not enforce all documented bucket restrictions.
# http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/index.html?BucketRestrictions.html
@attr('fails_on_aws')
# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='name begins with underscore')
@attr(assertion='fails with subdomain: 400')
def test_bucket_create_naming_bad_starts_nonalpha():
    bucket_name = get_new_bucket_name()
    check_bad_bucket_name('_' + bucket_name)

def check_invalid_bucketname(invalid_name):
    """
    Send a create bucket_request with an invalid bucket name
    that will bypass the ParamValidationError that would be raised
    if the invalid bucket name that was passed in normally.
    This function returns the status and error code from the failure
    """
    client = get_client()
    valid_bucket_name = get_new_bucket_name()
    def replace_bucketname_from_url(**kwargs):
        url = kwargs['params']['url']
        new_url = url.replace(valid_bucket_name, invalid_name)
        kwargs['params']['url'] = new_url
    client.meta.events.register('before-call.s3.CreateBucket', replace_bucketname_from_url)
    e = assert_raises(ClientError, client.create_bucket, Bucket=invalid_name)
    status, error_code = _get_status_and_error_code(e.response)
    return (status, error_code)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='empty name')
@attr(assertion='fails 405')
# TODO: remove this fails_on_rgw when I fix it
@attr('fails_on_rgw')
def test_bucket_create_naming_bad_short_empty():
    invalid_bucketname = ''
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 405)
    eq(error_code, 'MethodNotAllowed')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='short (one character) name')
@attr(assertion='fails 400')
def test_bucket_create_naming_bad_short_one():
    check_bad_bucket_name('a')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='short (two character) name')
@attr(assertion='fails 400')
def test_bucket_create_naming_bad_short_two():
    check_bad_bucket_name('aa')

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='excessively long names')
@attr(assertion='fails with subdomain: 400')
# TODO: remove this fails_on_rgw when I fix it
@attr('fails_on_rgw')
def test_bucket_create_naming_bad_long():
    invalid_bucketname = 256*'a'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)

    invalid_bucketname = 280*'a'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)

    invalid_bucketname = 3000*'a'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)

def check_good_bucket_name(name, _prefix=None):
    """
    Attempt to create a bucket with a specified name
    and (specified or default) prefix, returning the
    results of that effort.
    """
    # tests using this with the default prefix must *not* rely on
    # being able to set the initial character, or exceed the max len

    # tests using this with a custom prefix are responsible for doing
    # their own setup/teardown nukes, with their custom prefix; this
    # should be very rare
    if _prefix is None:
        _prefix = get_prefix()
    bucket_name = '{prefix}{name}'.format(
            prefix=_prefix,
            name=name,
            )
    client = get_client()
    response = client.create_bucket(Bucket=bucket_name)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

def _test_bucket_create_naming_good_long(length):
    """
    Attempt to create a bucket whose name (including the
    prefix) is of a specified length.
    """
    # tests using this with the default prefix must *not* rely on
    # being able to set the initial character, or exceed the max len

    # tests using this with a custom prefix are responsible for doing
    # their own setup/teardown nukes, with their custom prefix; this
    # should be very rare
    prefix = get_new_bucket_name()
    assert len(prefix) < 63
    num = length - len(prefix)
    name=num*'a'

    bucket_name = '{prefix}{name}'.format(
            prefix=prefix,
            name=name,
            )
    client = get_client()
    response = client.create_bucket(Bucket=bucket_name)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/60 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_good_long_60():
    _test_bucket_create_naming_good_long(60)

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/61 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_good_long_61():
    _test_bucket_create_naming_good_long(61)

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/62 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_good_long_62():
    _test_bucket_create_naming_good_long(62)


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/63 byte name')
@attr(assertion='fails with subdomain')
def test_bucket_create_naming_good_long_63():
    _test_bucket_create_naming_good_long(63)


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='get')
@attr(operation='list w/61 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_list_long_name():
    prefix = get_new_bucket_name()
    length = 61
    num = length - len(prefix)
    name=num*'a'

    bucket_name = '{prefix}{name}'.format(
            prefix=prefix,
            name=name,
            )
    bucket = get_new_bucket_resource(name=bucket_name)
    is_empty = _bucket_is_empty(bucket)
    eq(is_empty, True)

# AWS does not enforce all documented bucket restrictions.
# http://docs.amazonwebservices.com/AmazonS3/2006-03-01/dev/index.html?BucketRestrictions.html
@attr('fails_on_aws')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/ip address for name')
@attr(assertion='fails on aws')
def test_bucket_create_naming_bad_ip():
    check_bad_bucket_name('192.168.5.123')

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/! in name')
@attr(assertion='fails with subdomain')
# TODO: remove this fails_on_rgw when I fix it
@attr('fails_on_rgw')
def test_bucket_create_naming_bad_punctuation():
    # characters other than [a-zA-Z0-9._-]
    invalid_bucketname = 'alpha!soup'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    # TODO: figure out why a 403 is coming out in boto3 but not in boto2.
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')

# test_bucket_create_naming_dns_* are valid but not recommended
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/underscore in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_underscore():
    invalid_bucketname = 'foo_bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/100 byte name')
@attr(assertion='fails with subdomain')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
def test_bucket_create_naming_dns_long():
    prefix = get_prefix()
    assert len(prefix) < 50
    num = 63 - len(prefix)
    check_good_bucket_name(num * 'a')

# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/dash at end of name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dash_at_end():
    invalid_bucketname = 'foo-'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/.. in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dot_dot():
    invalid_bucketname = 'foo..bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/.- in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dot_dash():
    invalid_bucketname = 'foo.-bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')


# Breaks DNS with SubdomainCallingFormat
@attr('fails_with_subdomain')
@attr(resource='bucket')
@attr(method='put')
@attr(operation='create w/-. in name')
@attr(assertion='fails')
@attr('fails_on_aws') # <Error><Code>InvalidBucketName</Code><Message>The specified bucket is not valid.</Message>...</Error>
# Should now pass on AWS even though it has 'fails_on_aws' attr.
def test_bucket_create_naming_dns_dash_dot():
    invalid_bucketname = 'foo-.bar'
    status, error_code = check_invalid_bucketname(invalid_bucketname)
    eq(status, 400)
    eq(error_code, 'InvalidBucketName')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='re-create')
def test_bucket_create_exists():
    # aws-s3 default region allows recreation of buckets
    # but all other regions fail with BucketAlreadyOwnedByYou.
    bucket_name = get_new_bucket_name()
    client = get_client()

    client.create_bucket(Bucket=bucket_name)
    try:
        response = client.create_bucket(Bucket=bucket_name)
    except ClientError as e:
        status, error_code = _get_status_and_error_code(e.response)
        eq(e.status, 409)
        eq(e.error_code, 'BucketAlreadyOwnedByYou')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='get location')
def test_bucket_get_location():
    location_constraint = get_main_api_name()
    if not location_constraint:
        raise SkipTest
    bucket_name = get_new_bucket_name()
    client = get_client()

    client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': location_constraint})

    response = client.get_bucket_location(Bucket=bucket_name)
    if location_constraint == "":
        location_constraint = None
    eq(response['LocationConstraint'], location_constraint)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name starts with alphabetic works')
# this test goes outside the user-configure prefix because it needs to
# control the initial character of the bucket name
@nose.with_setup(
    setup=lambda: nuke_prefixed_buckets(prefix='a'+get_prefix()),
    teardown=lambda: nuke_prefixed_buckets(prefix='a'+get_prefix()),
    )
def test_bucket_create_naming_good_starts_alpha():
    check_good_bucket_name('foo', _prefix='a'+get_prefix())

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name starts with numeric works')
# this test goes outside the user-configure prefix because it needs to
# control the initial character of the bucket name
@nose.with_setup(
    setup=lambda: nuke_prefixed_buckets(prefix='0'+get_prefix()),
    teardown=lambda: nuke_prefixed_buckets(prefix='0'+get_prefix()),
    )
def test_bucket_create_naming_good_starts_digit():
    check_good_bucket_name('foo', _prefix='0'+get_prefix())

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name containing dot works')
def test_bucket_create_naming_good_contains_period():
    check_good_bucket_name('aaa.111')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket')
@attr(assertion='name containing hyphen works')
def test_bucket_create_naming_good_contains_hyphen():
    check_good_bucket_name('aaa-111')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='create bucket with objects and recreate it')
@attr(assertion='bucket recreation not overriding index')
def test_bucket_recreate_not_overriding():
    key_names = ['mykey1', 'mykey2']
    bucket_name = _create_objects(keys=key_names)

    objs_list = get_objects_list(bucket_name)
    eq(key_names, objs_list)

    client = get_client()
    client.create_bucket(Bucket=bucket_name)

    objs_list = get_objects_list(bucket_name)
    eq(key_names, objs_list)

@attr(resource='object')
@attr(method='put')
@attr(operation='create and list objects with special names')
@attr(assertion='special names work')
def test_bucket_create_special_key_names():
    key_names = [
        ' ',
        '"',
        '$',
        '%',
        '&',
        '\'',
        '<',
        '>',
        '_',
        '_ ',
        '_ _',
        '__',
    ]

    bucket_name = _create_objects(keys=key_names)

    objs_list = get_objects_list(bucket_name)
    eq(key_names, objs_list)

    client = get_client()

    for name in key_names:
        eq((name in objs_list), True)
        response = client.get_object(Bucket=bucket_name, Key=name)
        body = _get_body(response)
        eq(name, body)
        client.put_object_acl(Bucket=bucket_name, Key=name, ACL='private')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='re-create by non-owner')
@attr(assertion='fails 409')
def test_bucket_create_exists_nonowner():
    # Names are shared across a global namespace. As such, no two
    # users can create a bucket with that same name.
    bucket_name = get_new_bucket_name()
    client = get_client()

    alt_client = get_alt_client()

    client.create_bucket(Bucket=bucket_name)
    e = assert_raises(ClientError, alt_client.create_bucket, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 409)
    eq(error_code, 'BucketAlreadyExists')

def check_access_denied(fn, *args, **kwargs):
    e = assert_raises(ClientError, fn, *args, **kwargs)
    status = _get_status(e.response)
    eq(status, 403)

def check_grants(got, want):
    """
    Check that grants list in got matches the dictionaries in want,
    in any order.
    """
    eq(len(got), len(want))
    for g, w in zip(got, want):
        w = dict(w)
        g = dict(g)
        eq(g.pop('Permission', None), w['Permission'])
        eq(g['Grantee'].pop('DisplayName', None), w['DisplayName'])
        eq(g['Grantee'].pop('ID', None), w['ID'])
        eq(g['Grantee'].pop('Type', None), w['Type'])
        eq(g['Grantee'].pop('URI', None), w['URI'])
        eq(g['Grantee'].pop('EmailAddress', None), w['EmailAddress'])
        eq(g, {'Grantee': {}})

@attr(resource='bucket')
@attr(method='get')
@attr(operation='default acl')
@attr(assertion='read back expected defaults')
def test_bucket_acl_default():
    bucket_name = get_new_bucket()
    client = get_client()

    response = client.get_bucket_acl(Bucket=bucket_name)

    display_name = get_main_display_name()
    user_id = get_main_user_id()

    eq(response['Owner']['DisplayName'], display_name)
    eq(response['Owner']['ID'], user_id)

    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

@attr(resource='bucket')
@attr(method='get')
@attr(operation='public-read acl')
@attr(assertion='read back expected defaults')
@attr('fails_on_aws') # <Error><Code>IllegalLocationConstraintException</Code><Message>The unspecified location constraint is incompatible for the region specific endpoint this request was sent to.</Message>
def test_bucket_acl_canned_during_create():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read', Bucket=bucket_name)
    response = client.get_bucket_acl(Bucket=bucket_name)

    display_name = get_main_display_name()
    user_id = get_main_user_id()

    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission='READ',
                ID=None,
                DisplayName=None,
                URI='http://acs.amazonaws.com/groups/global/AllUsers',
                EmailAddress=None,
                Type='Group',
                ),
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

@attr(resource='bucket')
@attr(method='put')
@attr(operation='acl: public-read,private')
@attr(assertion='read back expected values')
def test_bucket_acl_canned():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read', Bucket=bucket_name)
    response = client.get_bucket_acl(Bucket=bucket_name)

    display_name = get_main_display_name()
    user_id = get_main_user_id()

    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission='READ',
                ID=None,
                DisplayName=None,
                URI='http://acs.amazonaws.com/groups/global/AllUsers',
                EmailAddress=None,
                Type='Group',
                ),
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

    client.put_bucket_acl(ACL='private', Bucket=bucket_name)
    response = client.get_bucket_acl(Bucket=bucket_name)

    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

@attr(resource='bucket.acls')
@attr(method='put')
@attr(operation='acl: public-read-write')
@attr(assertion='read back expected values')
def test_bucket_acl_canned_publicreadwrite():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)
    response = client.get_bucket_acl(Bucket=bucket_name)

    display_name = get_main_display_name()
    user_id = get_main_user_id()
    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission='READ',
                ID=None,
                DisplayName=None,
                URI='http://acs.amazonaws.com/groups/global/AllUsers',
                EmailAddress=None,
                Type='Group',
                ),
            dict(
                Permission='WRITE',
                ID=None,
                DisplayName=None,
                URI='http://acs.amazonaws.com/groups/global/AllUsers',
                EmailAddress=None,
                Type='Group',
                ),
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

@attr(resource='bucket')
@attr(method='put')
@attr(operation='acl: authenticated-read')
@attr(assertion='read back expected values')
def test_bucket_acl_canned_authenticatedread():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='authenticated-read', Bucket=bucket_name)
    response = client.get_bucket_acl(Bucket=bucket_name)

    display_name = get_main_display_name()
    user_id = get_main_user_id()

    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission='READ',
                ID=None,
                DisplayName=None,
                URI='http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
                EmailAddress=None,
                Type='Group',
                ),
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

@attr(resource='bucket')
@attr(method='ACLs')
@attr(operation='set acl private')
@attr(assertion='a private object can be set to private')
def test_bucket_acl_canned_private_to_private():
    bucket_name = get_new_bucket()
    client = get_client()

    response = client.put_bucket_acl(Bucket=bucket_name, ACL='private')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all buckets')
@attr(assertion='returns all expected buckets')
def test_buckets_create_then_list():
    client = get_client()
    bucket_names = []
    for i in range(5):
        bucket_name = get_new_bucket_name()
        bucket_names.append(bucket_name)

    for name in bucket_names:
        client.create_bucket(Bucket=name)

    response = client.list_buckets()
    bucket_dicts = response['Buckets']
    buckets_list = []

    buckets_list = get_buckets_list()

    for name in bucket_names:
        if name not in buckets_list:
            raise RuntimeError("S3 implementation's GET on Service did not return bucket we created: %r", bucket.name)

@attr(resource='bucket')
@attr(method='del')
@attr(operation='deleted bucket')
@attr(assertion='fails 404')
def test_bucket_create_delete():
    bucket_name = get_new_bucket()
    client = get_client()
    client.delete_bucket(Bucket=bucket_name)

    e = assert_raises(ClientError, client.delete_bucket, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='bucket')
@attr(method='head')
@attr(operation='head bucket')
@attr(assertion='succeeds')
def test_bucket_head():
    bucket_name = get_new_bucket()
    client = get_client()

    response = client.head_bucket(Bucket=bucket_name)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='empty buckets return no contents')
def test_bucket_list_empty():
    bucket = get_new_bucket_resource()
    is_empty = _bucket_is_empty(bucket)
    eq(is_empty, True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='distinct buckets have different contents')
def test_bucket_list_distinct():
    bucket1 = get_new_bucket_resource()
    bucket2 = get_new_bucket_resource()
    obj = bucket1.put_object(Body='str', Key='asdf')
    is_empty = _bucket_is_empty(bucket2)
    eq(is_empty, True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=2, no marker')
def test_bucket_list_many():
    bucket_name = _create_objects(keys=['foo', 'bar', 'baz'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 2)
    eq(keys, ['bar', 'baz'])
    eq(response['IsTruncated'], True)

    response = client.list_objects(Bucket=bucket_name, Marker='baz',MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 1)
    eq(response['IsTruncated'], False)
    eq(keys, ['foo'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=2, no marker')
@attr('list-objects-v2')
def test_bucket_listv2_many():
    bucket_name = _create_objects(keys=['foo', 'bar', 'baz'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 2)
    eq(keys, ['bar', 'baz'])
    eq(response['IsTruncated'], True)

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='baz',MaxKeys=2)
    keys = _get_keys(response)
    eq(len(keys), 1)
    eq(response['IsTruncated'], False)
    eq(keys, ['foo'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='keycount in listobjectsv2')
@attr('list-objects-v2')
def test_basic_key_count():
    client = get_client()
    bucket_names = []
    bucket_name = get_new_bucket_name()
    client.create_bucket(Bucket=bucket_name)
    for j in range(5):
            client.put_object(Bucket=bucket_name, Key=str(j))
    response1 = client.list_objects_v2(Bucket=bucket_name)
    eq(response1['KeyCount'], 5)

def _get_keys(response):
    """
    return lists of strings that are the keys from a client.list_objects() response
    """
    keys = []
    if 'Contents' in response:
        objects_list = response['Contents']
        keys = [obj['Key'] for obj in objects_list]
    return keys

def _get_prefixes(response):
    """
    return lists of strings that are prefixes from a client.list_objects() response
    """
    prefixes = []
    if 'CommonPrefixes' in response:
        prefix_list = response['CommonPrefixes']
        prefixes = [prefix['Prefix'] for prefix in prefix_list]
    return prefixes

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes in multi-component object names')
def test_bucket_list_delimiter_basic():
    bucket_name = _create_objects(keys=['foo/bar', 'foo/bar/xyzzy', 'quux/thud', 'asdf'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/')
    eq(response['Delimiter'], '/')
    keys = _get_keys(response)
    eq(keys, ['asdf'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['foo/', 'quux/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes in multi-component object names')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_basic():
    bucket_name = _create_objects(keys=['foo/bar', 'foo/bar/xyzzy', 'quux/thud', 'asdf'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='/')
    eq(response['Delimiter'], '/')
    keys = _get_keys(response)
    eq(keys, ['asdf'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['foo/', 'quux/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='test url encoding')
@attr('list-objects-v2')
def test_bucket_listv2_encoding_basic():
    bucket_name = _create_objects(keys=['foo+1/bar', 'foo/bar/xyzzy', 'quux ab/thud', 'asdf+b'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='/', EncodingType='url')
    eq(response['Delimiter'], '/')
    keys = _get_keys(response)
    eq(keys, ['asdf%2Bb'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 3)
    eq(prefixes, ['foo%2B1/', 'foo/', 'quux%20ab/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='test url encoding')
@attr('list-objects')
def test_bucket_list_encoding_basic():
    bucket_name = _create_objects(keys=['foo+1/bar', 'foo/bar/xyzzy', 'quux ab/thud', 'asdf+b'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/', EncodingType='url')
    eq(response['Delimiter'], '/')
    keys = _get_keys(response)
    eq(keys, ['asdf%2Bb'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 3)
    eq(prefixes, ['foo%2B1/', 'foo/', 'quux%20ab/'])

def validate_bucket_list(bucket_name, prefix, delimiter, marker, max_keys,
                         is_truncated, check_objs, check_prefixes, next_marker):
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter=delimiter, Marker=marker, MaxKeys=max_keys, Prefix=prefix)
    eq(response['IsTruncated'], is_truncated)
    if 'NextMarker' not in response:
        response['NextMarker'] = None
    eq(response['NextMarker'], next_marker)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)

    eq(len(keys), len(check_objs))
    eq(len(prefixes), len(check_prefixes))
    eq(keys, check_objs)
    eq(prefixes, check_prefixes)

    return response['NextMarker']

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes in multi-component object names')
def test_bucket_list_delimiter_prefix():
    bucket_name = _create_objects(keys=['asdf', 'boo/bar', 'boo/baz/xyzzy', 'cquux/thud', 'cquux/bla'])

    delim = '/'
    marker = ''
    prefix = ''
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 1, True, ['asdf'], [], 'asdf')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 1, True, [], ['boo/'], 'boo/')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 1, False, [], ['cquux/'], None)
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 2, True, ['asdf'], ['boo/'], 'boo/')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 2, False, [], ['cquux/'], None)
    
    prefix = 'boo/'
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 1, True, ['boo/bar'], [], 'boo/bar')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 1, False, [], ['boo/baz/'], None)
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 2, False, ['boo/bar'], ['boo/baz/'], None)

def validate_bucket_listv2(bucket_name, prefix, delimiter, continuation_token, max_keys,
                         is_truncated, check_objs, check_prefixes, last=False):
    client = get_client()

    params = dict(Bucket=bucket_name, Delimiter=delimiter, MaxKeys=max_keys, Prefix=prefix)
    if continuation_token is not None:
        params['ContinuationToken'] = continuation_token
    else:
        params['StartAfter'] = ''
    response = client.list_objects_v2(**params)
    eq(response['IsTruncated'], is_truncated)
    if 'NextContinuationToken' not in response:
        response['NextContinuationToken'] = None
    if last:
        eq(response['NextContinuationToken'], None)


    keys = _get_keys(response)
    prefixes = _get_prefixes(response)

    eq(len(keys), len(check_objs))
    eq(len(prefixes), len(check_prefixes))
    eq(keys, check_objs)
    eq(prefixes, check_prefixes)

    return response['NextContinuationToken']

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefix and delimiter handling when object ends with delimiter')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_prefix_ends_with_delimiter():
    bucket_name = _create_objects(keys=['asdf/'])
    validate_bucket_listv2(bucket_name, 'asdf/', '/', None, 1000, False, ['asdf/'], [], last=True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefix and delimiter handling when object ends with delimiter')
def test_bucket_list_delimiter_prefix_ends_with_delimiter():
    bucket_name = _create_objects(keys=['asdf/'])
    validate_bucket_list(bucket_name, 'asdf/', '/', '', 1000, False, ['asdf/'], [], None)


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes in multi-component object names')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_prefix():
    bucket_name = _create_objects(keys=['asdf', 'boo/bar', 'boo/baz/xyzzy', 'cquux/thud', 'cquux/bla'])

    delim = '/'
    continuation_token = ''
    prefix = ''
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['asdf'], [])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 1, True, [], ['boo/'])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 1, False, [], ['cquux/'], last=True)
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, True, ['asdf'], ['boo/'])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 2, False, [], ['cquux/'], last=True)

    prefix = 'boo/'
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['boo/bar'], [])
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token, 1, False, [], ['boo/baz/'], last=True)
    continuation_token = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, False, ['boo/bar'], ['boo/baz/'], last=True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='non-slash delimiter characters')
def test_bucket_list_delimiter_alt():
    bucket_name = _create_objects(keys=['bar', 'baz', 'cab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='a')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    # bar, baz, and cab should be broken up by the 'a' delimiters
    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['ba', 'ca'])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='non-slash delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_alt():
    bucket_name = _create_objects(keys=['bar', 'baz', 'cab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='a')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    # bar, baz, and cab should be broken up by the 'a' delimiters
    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    eq(prefixes, ['ba', 'ca'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes starting with underscore')
def test_bucket_list_delimiter_prefix_underscore():
    bucket_name = _create_objects(keys=['_obj1_','_under1/bar', '_under1/baz/xyzzy', '_under2/thud', '_under2/bla'])

    delim = '/'
    marker = ''
    prefix = ''
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 1, True, ['_obj1_'], [], '_obj1_')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 1, True, [], ['_under1/'], '_under1/')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 1, False, [], ['_under2/'], None)
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 2, True, ['_obj1_'], ['_under1/'], '_under1/')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 2, False, [], ['_under2/'], None)

    prefix = '_under1/'
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 1, True, ['_under1/bar'], [], '_under1/bar')
    marker = validate_bucket_list(bucket_name, prefix, delim, marker, 1, False, [], ['_under1/baz/'], None)
    marker = validate_bucket_list(bucket_name, prefix, delim, '', 2, False, ['_under1/bar'], ['_under1/baz/'], None)


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='prefixes starting with underscore')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_prefix_underscore():
    bucket_name = _create_objects(keys=['_obj1_','_under1/bar', '_under1/baz/xyzzy', '_under2/thud', '_under2/bla'])

    delim = '/'
    continuation_token = ''
    prefix = ''
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['_obj1_'], [])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 1, True, [], ['_under1/'])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 1, False, [], ['_under2/'], last=True)
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, True, ['_obj1_'], ['_under1/'])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 2, False, [], ['_under2/'], last=True)

    prefix = '_under1/'
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 1, True, ['_under1/bar'], [])
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, continuation_token , 1, False, [], ['_under1/baz/'], last=True)
    continuation_token  = validate_bucket_listv2(bucket_name, prefix, delim, None, 2, False, ['_under1/bar'], ['_under1/baz/'], last=True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='percentage delimiter characters')
def test_bucket_list_delimiter_percentage():
    bucket_name = _create_objects(keys=['b%ar', 'b%az', 'c%ab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='%')
    eq(response['Delimiter'], '%')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b%', 'c%'])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='percentage delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_percentage():
    bucket_name = _create_objects(keys=['b%ar', 'b%az', 'c%ab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='%')
    eq(response['Delimiter'], '%')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b%', 'c%'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='whitespace delimiter characters')
def test_bucket_list_delimiter_whitespace():
    bucket_name = _create_objects(keys=['b ar', 'b az', 'c ab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter=' ')
    eq(response['Delimiter'], ' ')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b ', 'c '])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='whitespace delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_whitespace():
    bucket_name = _create_objects(keys=['b ar', 'b az', 'c ab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter=' ')
    eq(response['Delimiter'], ' ')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b ', 'c '])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='dot delimiter characters')
def test_bucket_list_delimiter_dot():
    bucket_name = _create_objects(keys=['b.ar', 'b.az', 'c.ab', 'foo'])
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='.')
    eq(response['Delimiter'], '.')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b.', 'c.'])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='dot delimiter characters')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_dot():
    bucket_name = _create_objects(keys=['b.ar', 'b.az', 'c.ab', 'foo'])
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='.')
    eq(response['Delimiter'], '.')
    keys = _get_keys(response)
    # foo contains no 'a' and so is a complete key
    eq(keys, ['foo'])

    prefixes = _get_prefixes(response)
    eq(len(prefixes), 2)
    # bar, baz, and cab should be broken up by the 'a' delimiters
    eq(prefixes, ['b.', 'c.'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='non-printable delimiter can be specified')
def test_bucket_list_delimiter_unreadable():
    key_names=['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='\x0a')
    eq(response['Delimiter'], '\x0a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='non-printable delimiter can be specified')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_unreadable():
    key_names=['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='\x0a')
    eq(response['Delimiter'], '\x0a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='empty delimiter can be specified')
def test_bucket_list_delimiter_empty():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='')
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='empty delimiter can be specified')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_empty():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='')
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='unspecified delimiter defaults to none')
def test_bucket_list_delimiter_none():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name)
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='unspecified delimiter defaults to none')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_none():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name)
    # putting an empty value into Delimiter will not return a value in the response
    eq('Delimiter' in response, False)

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='unused delimiter is not found')
def test_bucket_list_delimiter_not_exist():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/')
    # putting an empty value into Delimiter will not return a value in the response
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(assertion='unused delimiter is not found')
@attr('list-objects-v2')
def test_bucket_listv2_delimiter_not_exist():
    key_names = ['bar', 'baz', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='/')
    # putting an empty value into Delimiter will not return a value in the response
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list')
@attr(assertion='list with delimiter not skip special keys')
def test_bucket_list_delimiter_not_skip_special():
    key_names = ['0/'] + ['0/%s' % i for i in range(1000, 1999)]
    key_names2 = ['1999', '1999#', '1999+', '2000']
    key_names += key_names2
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/')
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names2)
    eq(prefixes, ['0/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='returns onl  y objects under prefix')
def test_bucket_list_prefix_basic():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='foo/')
    eq(response['Prefix'], 'foo/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar', 'foo/baz'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='returns only objects under prefix')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_basic():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='foo/')
    eq(response['Prefix'], 'foo/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar', 'foo/baz'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='prefixes w/o delimiters')
def test_bucket_list_prefix_alt():
    key_names = ['bar', 'baz', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='ba')
    eq(response['Prefix'], 'ba')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar', 'baz'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='prefixes w/o delimiters')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_alt():
    key_names = ['bar', 'baz', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='ba')
    eq(response['Prefix'], 'ba')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar', 'baz'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='empty prefix returns everything')
def test_bucket_list_prefix_empty():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='empty prefix returns everything')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_empty():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='unspecified prefix returns everything')
def test_bucket_list_prefix_none():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='unspecified prefix returns everything')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_none():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='')
    eq(response['Prefix'], '')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, key_names)
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='nonexistent prefix returns nothing')
def test_bucket_list_prefix_not_exist():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='d')
    eq(response['Prefix'], 'd')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='nonexistent prefix returns nothing')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_not_exist():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='d')
    eq(response['Prefix'], 'd')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix')
@attr(assertion='non-printable prefix can be specified')
def test_bucket_list_prefix_unreadable():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Prefix='\x0a')
    eq(response['Prefix'], '\x0a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix with list-objects-v2')
@attr(assertion='non-printable prefix can be specified')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_unreadable():
    key_names = ['foo/bar', 'foo/baz', 'quux']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Prefix='\x0a')
    eq(response['Prefix'], '\x0a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='returns only objects directly under prefix')
def test_bucket_list_prefix_delimiter_basic():
    key_names = ['foo/bar', 'foo/baz/xyzzy', 'quux/thud', 'asdf']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='/', Prefix='foo/')
    eq(response['Prefix'], 'foo/')
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar'])
    eq(prefixes, ['foo/baz/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='returns only objects directly under prefix')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_basic():
    key_names = ['foo/bar', 'foo/baz/xyzzy', 'quux/thud', 'asdf']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='/', Prefix='foo/')
    eq(response['Prefix'], 'foo/')
    eq(response['Delimiter'], '/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['foo/bar'])
    eq(prefixes, ['foo/baz/'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='non-slash delimiters')
def test_bucket_list_prefix_delimiter_alt():
    key_names = ['bar', 'bazar', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='a', Prefix='ba')
    eq(response['Prefix'], 'ba')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar'])
    eq(prefixes, ['baza'])

@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_alt():
    key_names = ['bar', 'bazar', 'cab', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='a', Prefix='ba')
    eq(response['Prefix'], 'ba')
    eq(response['Delimiter'], 'a')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['bar'])
    eq(prefixes, ['baza'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix')
def test_bucket_list_prefix_delimiter_prefix_not_exist():
    key_names = ['b/a/r', 'b/a/c', 'b/a/g', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='d', Prefix='/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_prefix_not_exist():
    key_names = ['b/a/r', 'b/a/c', 'b/a/g', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='d', Prefix='/')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='over-ridden slash ceases to be a delimiter')
def test_bucket_list_prefix_delimiter_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='z', Prefix='b')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['b/a/c', 'b/a/g', 'b/a/r'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='over-ridden slash ceases to be a delimiter')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='z', Prefix='b')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, ['b/a/c', 'b/a/g', 'b/a/r'])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix and delimiter')
def test_bucket_list_prefix_delimiter_prefix_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Delimiter='z', Prefix='y')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list-objects-v2 under prefix w/delimiter')
@attr(assertion='finds nothing w/unmatched prefix and delimiter')
@attr('list-objects-v2')
def test_bucket_listv2_prefix_delimiter_prefix_delimiter_not_exist():
    key_names = ['b/a/c', 'b/a/g', 'b/a/r', 'g']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, Delimiter='z', Prefix='y')

    keys = _get_keys(response)
    prefixes = _get_prefixes(response)
    eq(keys, [])
    eq(prefixes, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=1, marker')
def test_bucket_list_maxkeys_one():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, MaxKeys=1)
    eq(response['IsTruncated'], True)

    keys = _get_keys(response)
    eq(keys, key_names[0:1])

    response = client.list_objects(Bucket=bucket_name, Marker=key_names[0])
    eq(response['IsTruncated'], False)

    keys = _get_keys(response)
    eq(keys, key_names[1:])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='pagination w/max_keys=1, marker')
@attr('list-objects-v2')
def test_bucket_listv2_maxkeys_one():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
    eq(response['IsTruncated'], True)

    keys = _get_keys(response)
    eq(keys, key_names[0:1])

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter=key_names[0])
    eq(response['IsTruncated'], False)

    keys = _get_keys(response)
    eq(keys, key_names[1:])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/max_keys=0')
def test_bucket_list_maxkeys_zero():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, MaxKeys=0)

    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='pagination w/max_keys=0')
@attr('list-objects-v2')
def test_bucket_listv2_maxkeys_zero():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=0)

    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='pagination w/o max_keys')
def test_bucket_list_maxkeys_none():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name)
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)
    eq(response['MaxKeys'], 1000)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='pagination w/o max_keys')
@attr('list-objects-v2')
def test_bucket_listv2_maxkeys_none():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name)
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)
    eq(response['MaxKeys'], 1000)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='bucket list unordered')
@attr('fails_on_aws') # allow-unordered is a non-standard extension
def test_bucket_list_unordered():
    # boto3.set_stream_logger(name='botocore')
    keys_in = ['ado', 'bot', 'cob', 'dog', 'emu', 'fez', 'gnu', 'hex',
               'abc/ink', 'abc/jet', 'abc/kin', 'abc/lax', 'abc/mux',
               'def/nim', 'def/owl', 'def/pie', 'def/qed', 'def/rye',
               'ghi/sew', 'ghi/tor', 'ghi/uke', 'ghi/via', 'ghi/wit',
               'xix', 'yak', 'zoo']
    bucket_name = _create_objects(keys=keys_in)
    client = get_client()

    # adds the unordered query parameter
    def add_unordered(**kwargs):
        kwargs['params']['url'] += "&allow-unordered=true"
    client.meta.events.register('before-call.s3.ListObjects', add_unordered)

    # test simple retrieval
    response = client.list_objects(Bucket=bucket_name, MaxKeys=1000)
    unordered_keys_out = _get_keys(response)
    eq(len(keys_in), len(unordered_keys_out))
    eq(keys_in.sort(), unordered_keys_out.sort())

    # test retrieval with prefix
    response = client.list_objects(Bucket=bucket_name,
                                   MaxKeys=1000,
                                   Prefix="abc/")
    unordered_keys_out = _get_keys(response)
    eq(5, len(unordered_keys_out))

    # test incremental retrieval with marker
    response = client.list_objects(Bucket=bucket_name, MaxKeys=6)
    unordered_keys_out = _get_keys(response)
    eq(6, len(unordered_keys_out))

    # now get the next bunch
    response = client.list_objects(Bucket=bucket_name,
                                   MaxKeys=6,
                                   Marker=unordered_keys_out[-1])
    unordered_keys_out2 = _get_keys(response)
    eq(6, len(unordered_keys_out2))

    # make sure there's no overlap between the incremental retrievals
    intersect = set(unordered_keys_out).intersection(unordered_keys_out2)
    eq(0, len(intersect))

    # verify that unordered used with delimiter results in error
    e = assert_raises(ClientError,
                      client.list_objects, Bucket=bucket_name, Delimiter="/")
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='bucket list unordered')
@attr('fails_on_aws') # allow-unordered is a non-standard extension
@attr('list-objects-v2')
def test_bucket_listv2_unordered():
    # boto3.set_stream_logger(name='botocore')
    keys_in = ['ado', 'bot', 'cob', 'dog', 'emu', 'fez', 'gnu', 'hex',
               'abc/ink', 'abc/jet', 'abc/kin', 'abc/lax', 'abc/mux',
               'def/nim', 'def/owl', 'def/pie', 'def/qed', 'def/rye',
               'ghi/sew', 'ghi/tor', 'ghi/uke', 'ghi/via', 'ghi/wit',
               'xix', 'yak', 'zoo']
    bucket_name = _create_objects(keys=keys_in)
    client = get_client()

    # adds the unordered query parameter
    def add_unordered(**kwargs):
        kwargs['params']['url'] += "&allow-unordered=true"
    client.meta.events.register('before-call.s3.ListObjects', add_unordered)

    # test simple retrieval
    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1000)
    unordered_keys_out = _get_keys(response)
    eq(len(keys_in), len(unordered_keys_out))
    eq(keys_in.sort(), unordered_keys_out.sort())

    # test retrieval with prefix
    response = client.list_objects_v2(Bucket=bucket_name,
                                   MaxKeys=1000,
                                   Prefix="abc/")
    unordered_keys_out = _get_keys(response)
    eq(5, len(unordered_keys_out))

    # test incremental retrieval with marker
    response = client.list_objects_v2(Bucket=bucket_name, MaxKeys=6)
    unordered_keys_out = _get_keys(response)
    eq(6, len(unordered_keys_out))

    # now get the next bunch
    response = client.list_objects_v2(Bucket=bucket_name,
                                   MaxKeys=6,
                                   StartAfter=unordered_keys_out[-1])
    unordered_keys_out2 = _get_keys(response)
    eq(6, len(unordered_keys_out2))

    # make sure there's no overlap between the incremental retrievals
    intersect = set(unordered_keys_out).intersection(unordered_keys_out2)
    eq(0, len(intersect))

    # verify that unordered used with delimiter results in error
    e = assert_raises(ClientError,
                      client.list_objects, Bucket=bucket_name, Delimiter="/")
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='invalid max_keys')
def test_bucket_list_maxkeys_invalid():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    # adds invalid max keys to url
    # before list_objects is called
    def add_invalid_maxkeys(**kwargs):
        kwargs['params']['url'] += "&max-keys=blah"
    client.meta.events.register('before-call.s3.ListObjects', add_invalid_maxkeys)

    e = assert_raises(ClientError, client.list_objects, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')



@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='no pagination, no marker')
def test_bucket_list_marker_none():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name)
    eq(response['Marker'], '')


@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='no pagination, empty marker')
def test_bucket_list_marker_empty():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='')
    eq(response['Marker'], '')
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='no pagination, empty continuationtoken')
@attr('list-objects-v2')
def test_bucket_listv2_continuationtoken_empty():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, ContinuationToken='')
    eq(response['ContinuationToken'], '')
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list keys with list-objects-v2')
@attr(assertion='no pagination, non-empty continuationtoken')
@attr('list-objects-v2')
def test_bucket_listv2_continuationtoken():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response1 = client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
    next_continuation_token = response1['NextContinuationToken']

    response2 = client.list_objects_v2(Bucket=bucket_name, ContinuationToken=next_continuation_token)
    eq(response2['ContinuationToken'], next_continuation_token)
    eq(response2['IsTruncated'], False)
    key_names2 = ['baz', 'foo', 'quxx']
    keys = _get_keys(response2)
    eq(keys, key_names2)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list keys with list-objects-v2')
@attr(assertion='no pagination, non-empty continuationtoken and startafter')
@attr('list-objects-v2')
def test_bucket_listv2_both_continuationtoken_startafter():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response1 = client.list_objects_v2(Bucket=bucket_name, StartAfter='bar', MaxKeys=1)
    next_continuation_token = response1['NextContinuationToken']

    response2 = client.list_objects_v2(Bucket=bucket_name, StartAfter='bar', ContinuationToken=next_continuation_token)
    eq(response2['ContinuationToken'], next_continuation_token)
    eq(response2['StartAfter'], 'bar')
    eq(response2['IsTruncated'], False)
    key_names2 = ['foo', 'quxx']
    keys = _get_keys(response2)
    eq(keys, key_names2)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='non-printing marker')
def test_bucket_list_marker_unreadable():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='\x0a')
    eq(response['Marker'], '\x0a')
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='non-printing startafter')
@attr('list-objects-v2')
def test_bucket_listv2_startafter_unreadable():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='\x0a')
    eq(response['StartAfter'], '\x0a')
    eq(response['IsTruncated'], False)
    keys = _get_keys(response)
    eq(keys, key_names)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='marker not-in-list')
def test_bucket_list_marker_not_in_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='blah')
    eq(response['Marker'], 'blah')
    keys = _get_keys(response)
    eq(keys, [ 'foo','quxx'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='startafter not-in-list')
@attr('list-objects-v2')
def test_bucket_listv2_startafter_not_in_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='blah')
    eq(response['StartAfter'], 'blah')
    keys = _get_keys(response)
    eq(keys, ['foo', 'quxx'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys')
@attr(assertion='marker after list')
def test_bucket_list_marker_after_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects(Bucket=bucket_name, Marker='zzz')
    eq(response['Marker'], 'zzz')
    keys = _get_keys(response)
    eq(response['IsTruncated'], False)
    eq(keys, [])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all keys with list-objects-v2')
@attr(assertion='startafter after list')
@attr('list-objects-v2')
def test_bucket_listv2_startafter_after_list():
    key_names = ['bar', 'baz', 'foo', 'quxx']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    response = client.list_objects_v2(Bucket=bucket_name, StartAfter='zzz')
    eq(response['StartAfter'], 'zzz')
    keys = _get_keys(response)
    eq(response['IsTruncated'], False)
    eq(keys, [])

def _compare_dates(datetime1, datetime2):
    """
    changes ms from datetime1 to 0, compares it to datetime2
    """
    # both times are in datetime format but datetime1 has
    # microseconds and datetime2 does not
    datetime1 = datetime1.replace(microsecond=0)
    eq(datetime1, datetime2)

@attr(resource='object')
@attr(method='head')
@attr(operation='compare w/bucket list')
@attr(assertion='return same metadata')
def test_bucket_list_return_data():
    key_names = ['bar', 'baz', 'foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    data = {}
    for key_name in key_names:
        obj_response = client.head_object(Bucket=bucket_name, Key=key_name)
        acl_response = client.get_object_acl(Bucket=bucket_name, Key=key_name)
        data.update({
            key_name: {
                'DisplayName': acl_response['Owner']['DisplayName'],
                'ID': acl_response['Owner']['ID'],
                'ETag': obj_response['ETag'],
                'LastModified': obj_response['LastModified'],
                'ContentLength': obj_response['ContentLength'],
                }
            })

    response  = client.list_objects(Bucket=bucket_name)
    objs_list = response['Contents']
    for obj in objs_list:
        key_name = obj['Key']
        key_data = data[key_name]
        eq(obj['ETag'],key_data['ETag'])
        eq(obj['Size'],key_data['ContentLength'])
        eq(obj['Owner']['DisplayName'],key_data['DisplayName'])
        eq(obj['Owner']['ID'],key_data['ID'])
        _compare_dates(obj['LastModified'],key_data['LastModified'])

# amazon is eventually consistent, retry a bit if failed
def check_configure_versioning_retry(bucket_name, status, expected_string):
    client = get_client()

    response = client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'MFADelete': 'Disabled','Status': status})

    read_status = None

    for i in range(5):
        try:
            response = client.get_bucket_versioning(Bucket=bucket_name)
            read_status = response['Status']
        except KeyError:
            read_status = None

        if (expected_string == read_status):
            break

        time.sleep(1)

    eq(expected_string, read_status)


@attr(resource='object')
@attr(method='head')
@attr(operation='compare w/bucket list when bucket versioning is configured')
@attr(assertion='return same metadata')
@attr('versioning')
def test_bucket_list_return_data_versioning():
    bucket_name = get_new_bucket()
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    key_names = ['bar', 'baz', 'foo']
    bucket_name = _create_objects(bucket_name=bucket_name,keys=key_names)

    client = get_client()
    data = {}

    for key_name in key_names:
        obj_response = client.head_object(Bucket=bucket_name, Key=key_name)
        acl_response = client.get_object_acl(Bucket=bucket_name, Key=key_name)
        data.update({
            key_name: {
                'ID': acl_response['Owner']['ID'],
                'DisplayName': acl_response['Owner']['DisplayName'],
                'ETag': obj_response['ETag'],
                'LastModified': obj_response['LastModified'],
                'ContentLength': obj_response['ContentLength'],
                'VersionId': obj_response['VersionId']
                }
            })

    response  = client.list_object_versions(Bucket=bucket_name)
    objs_list = response['Versions']

    for obj in objs_list:
        key_name = obj['Key']
        key_data = data[key_name]
        eq(obj['Owner']['DisplayName'],key_data['DisplayName'])
        eq(obj['ETag'],key_data['ETag'])
        eq(obj['Size'],key_data['ContentLength'])
        eq(obj['Owner']['ID'],key_data['ID'])
        eq(obj['VersionId'], key_data['VersionId'])
        _compare_dates(obj['LastModified'],key_data['LastModified'])

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all objects (anonymous)')
@attr(assertion='succeeds')
def test_bucket_list_objects_anonymous():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_bucket_acl(Bucket=bucket_name, ACL='public-read')

    unauthenticated_client = get_unauthenticated_client()
    unauthenticated_client.list_objects(Bucket=bucket_name)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all objects (anonymous) with list-objects-v2')
@attr(assertion='succeeds')
@attr('list-objects-v2')
def test_bucket_listv2_objects_anonymous():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_bucket_acl(Bucket=bucket_name, ACL='public-read')

    unauthenticated_client = get_unauthenticated_client()
    unauthenticated_client.list_objects_v2(Bucket=bucket_name)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all objects (anonymous)')
@attr(assertion='fails')
def test_bucket_list_objects_anonymous_fail():
    bucket_name = get_new_bucket()

    unauthenticated_client = get_unauthenticated_client()
    e = assert_raises(ClientError, unauthenticated_client.list_objects, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all objects (anonymous) with list-objects-v2')
@attr(assertion='fails')
@attr('list-objects-v2')
def test_bucket_listv2_objects_anonymous_fail():
    bucket_name = get_new_bucket()

    unauthenticated_client = get_unauthenticated_client()
    e = assert_raises(ClientError, unauthenticated_client.list_objects_v2, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='non-existant bucket')
@attr(assertion='fails 404')
def test_bucket_notexist():
    bucket_name = get_new_bucket_name()
    client = get_client()

    e = assert_raises(ClientError, client.list_objects, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='non-existant bucket with list-objects-v2')
@attr(assertion='fails 404')
@attr('list-objects-v2')
def test_bucketv2_notexist():
    bucket_name = get_new_bucket_name()
    client = get_client()

    e = assert_raises(ClientError, client.list_objects_v2, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='bucket')
@attr(method='delete')
@attr(operation='non-existant bucket')
@attr(assertion='fails 404')
def test_bucket_delete_notexist():
    bucket_name = get_new_bucket_name()
    client = get_client()

    e = assert_raises(ClientError, client.delete_bucket, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='bucket')
@attr(method='delete')
@attr(operation='non-empty bucket')
@attr(assertion='fails 409')
def test_bucket_delete_nonempty():
    key_names = ['foo']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()

    e = assert_raises(ClientError, client.delete_bucket, Bucket=bucket_name)

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 409)
    eq(error_code, 'BucketNotEmpty')

def _do_set_bucket_canned_acl(client, bucket_name, canned_acl, i, results):
    try:
        client.put_bucket_acl(ACL=canned_acl, Bucket=bucket_name)
        results[i] = True
    except:
        results[i] = False

def _do_set_bucket_canned_acl_concurrent(client, bucket_name, canned_acl, num, results):
    t = []
    for i in range(num):
        thr = threading.Thread(target = _do_set_bucket_canned_acl, args=(client, bucket_name, canned_acl, i, results))
        thr.start()
        t.append(thr)
    return t

def _do_wait_completion(t):
    for thr in t:
        thr.join()

@attr(resource='bucket')
@attr(method='put')
@attr(operation='concurrent set of acls on a bucket')
@attr(assertion='works')
def test_bucket_concurrent_set_canned_acl():
    bucket_name = get_new_bucket()
    client = get_client()

    num_threads = 50 # boto2 retry defaults to 5 so we need a thread to fail at least 5 times
                     # this seems like a large enough number to get through retry (if bug
                     # exists)
    results = [None] * num_threads

    t = _do_set_bucket_canned_acl_concurrent(client, bucket_name, 'public-read', num_threads, results)
    _do_wait_completion(t)

    for r in results:
        eq(r, True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all buckets (anonymous)')
@attr(assertion='succeeds')
@attr('fails_on_aws')
def test_list_buckets_anonymous():
    # Get a connection with bad authorization, then change it to be our new Anonymous auth mechanism,
    # emulating standard HTTP access.
    #
    # While it may have been possible to use httplib directly, doing it this way takes care of also
    # allowing us to vary the calling format in testing.
    unauthenticated_client = get_unauthenticated_client()
    response = unauthenticated_client.list_buckets()
    eq(len(response['Buckets']), 0)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all buckets (bad auth)')
@attr(assertion='fails 403')
def test_list_buckets_invalid_auth():
    bad_auth_client = get_bad_auth_client()
    e = assert_raises(ClientError, bad_auth_client.list_buckets)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'InvalidAccessKeyId')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='list all buckets (bad auth)')
@attr(assertion='fails 403')
def test_list_buckets_bad_auth():
    main_access_key = get_main_aws_access_key()
    bad_auth_client = get_bad_auth_client(aws_access_key_id=main_access_key)
    e = assert_raises(ClientError, bad_auth_client.list_buckets)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'SignatureDoesNotMatch')