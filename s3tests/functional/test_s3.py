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

http_response = None

@attr(resource='object')
@attr(method='post')
@attr(operation='delete multiple objects with list-objects-v2')
@attr(assertion='deletes multiple objects with a single call')
@attr('list-objects-v2')
def test_multi_objectv2_delete():
    key_names = ['key0', 'key1', 'key2']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()
    response = client.list_objects_v2(Bucket=bucket_name)
    eq(len(response['Contents']), 3)

    objs_dict = _make_objs_dict(key_names=key_names)
    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)

    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects_v2(Bucket=bucket_name)
    assert 'Contents' not in response

    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)
    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects_v2(Bucket=bucket_name)
    assert 'Contents' not in response

def _set_get_metadata(metadata, bucket_name=None):
    """
    create a new bucket new or use an existing
    name to create an object that bucket,
    set the meta1 property to a specified, value,
    and then re-read and return that property
    """
    if bucket_name is None:
        bucket_name = get_new_bucket()

    client = get_client()
    metadata_dict = {'meta1': metadata}
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar', Metadata=metadata_dict)

    response = client.get_object(Bucket=bucket_name, Key='foo')
    return response['Metadata']['meta1']

def _get_post_url(bucket_name):
    endpoint = get_config_endpoint()
    return '{endpoint}/{bucket_name}'.format(endpoint=endpoint, bucket_name=bucket_name)

@attr(resource='object')
@attr(method='post')
@attr(operation='anonymous browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
def test_post_object_anonymous_request():
    bucket_name = get_new_bucket_name()
    client = get_client()
    url = _get_post_url(bucket_name)
    payload = OrderedDict([("key" , "foo.txt"),("acl" , "public-read"),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)
    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
def test_post_object_authenticated_request():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request, no content-type header')
@attr(assertion='succeeds and returns written data')
def test_post_object_authenticated_no_content_type():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)


    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key="foo.txt")
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request, bad access key')
@attr(assertion='fails')
def test_post_object_authenticated_request_bad_access_key():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , 'foo'),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='anonymous browser based upload via POST request')
@attr(assertion='succeeds with status 201')
def test_post_object_set_success_code():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)

    url = _get_post_url(bucket_name)
    payload = OrderedDict([("key" , "foo.txt"),("acl" , "public-read"),\
    ("success_action_status" , "201"),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 201)
    message = ET.fromstring(r.content).find('Key')
    eq(message.text,'foo.txt')

@attr(resource='object')
@attr(method='post')
@attr(operation='anonymous browser based upload via POST request')
@attr(assertion='succeeds with status 204')
def test_post_object_set_invalid_success_code():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)

    url = _get_post_url(bucket_name)
    payload = OrderedDict([("key" , "foo.txt"),("acl" , "public-read"),\
    ("success_action_status" , "404"),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    content = r.content.decode()
    eq(content,'')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
def test_post_object_upload_larger_than_chunk():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 5*1024*1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    foo_string = 'foo' * 1024*1024

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', foo_string)])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, foo_string)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
def test_post_object_set_key_from_filename():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "${filename}"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('foo.txt', 'bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds with status 204')
def test_post_object_ignored_header():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),("x-ignore-foo" , "bar"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds with status 204')
def test_post_object_case_insensitive_condition_fields():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bUcKeT": bucket_name},\
    ["StArTs-WiTh", "$KeY", "foo"],\
    {"AcL": "private"},\
    ["StArTs-WiTh", "$CoNtEnT-TyPe", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    foo_string = 'foo' * 1024*1024

    payload = OrderedDict([ ("kEy" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("aCl" , "private"),("signature" , signature),("pOLICy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds with escaped leading $ and returns written data')
def test_post_object_escaped_field_values():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "\$foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='\$foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns redirect url')
def test_post_object_success_redirect_action():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)

    url = _get_post_url(bucket_name)
    redirect_url = _get_post_url(bucket_name)

    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["eq", "$success_action_redirect", redirect_url],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),("success_action_redirect" , redirect_url),\
    ('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 200)
    url = r.url
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    eq(url,
    '{rurl}?bucket={bucket}&key={key}&etag=%22{etag}%22'.format(rurl = redirect_url,\
    bucket = bucket_name, key = 'foo.txt', etag = response['ETag'].strip('"')))

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with invalid signature error')
def test_post_object_invalid_signature():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())[::-1]

    payload = OrderedDict([ ("key" , "\$foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with access key does not exist error')
def test_post_object_invalid_access_key():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "\$foo.txt"),("AWSAccessKeyId" , aws_access_key_id[::-1]),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with invalid expiration error')
def test_post_object_invalid_date_format():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": str(expires),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "\$foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with missing key error')
def test_post_object_no_key_specified():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with missing signature error')
def test_post_object_missing_signature():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with extra input fields policy error')
def test_post_object_missing_policy_condition():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    ["starts-with", "$key", "\$foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024]\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds using starts-with restriction on metadata header')
def test_post_object_user_specified_header():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ["starts-with", "$x-amz-meta-foo",  "bar"]
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('x-amz-meta-foo' , 'barclamp'),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    eq(response['Metadata']['foo'], 'barclamp')

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with policy condition failed error due to missing field in POST request')
def test_post_object_request_missing_policy_specified_field():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ["starts-with", "$x-amz-meta-foo",  "bar"]
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with conditions must be list error')
def test_post_object_condition_is_case_sensitive():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "CONDITIONS": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with expiration must be string error')
def test_post_object_expires_is_case_sensitive():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"EXPIRATION": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with policy expired error')
def test_post_object_expired_policy():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=-6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key", "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails using equality restriction on metadata header')
def test_post_object_invalid_request_field_value():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ["eq", "$x-amz-meta-foo",  ""]
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())
    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('x-amz-meta-foo' , 'barclamp'),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 403)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with policy missing expiration error')
def test_post_object_missing_expires_condition():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 1024],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with policy missing conditions error')
def test_post_object_missing_conditions_list():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ")}

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with allowable upload size exceeded error')
def test_post_object_upload_size_limit_exceeded():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0, 0],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with invalid content length error')
def test_post_object_missing_content_length_argument():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 0],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with invalid JSON error')
def test_post_object_invalid_content_length_argument():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", -1, 0],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='fails with upload size less than minimum allowable error')
def test_post_object_upload_size_below_minimum():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["content-length-range", 512, 1000],\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='empty conditions return appropriate error response')
def test_post_object_empty_conditions():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    { }\
    ]\
    }

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 400)

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Match: the latest ETag')
@attr(assertion='succeeds')
def test_get_object_ifmatch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    response = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    etag = response['ETag']

    response = client.get_object(Bucket=bucket_name, Key='foo', IfMatch=etag)
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Match: bogus ETag')
@attr(assertion='fails 412')
def test_get_object_ifmatch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfMatch='"ABCORZ"')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-None-Match: the latest ETag')
@attr(assertion='fails 304')
def test_get_object_ifnonematch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    response = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    etag = response['ETag']

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfNoneMatch=etag)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 304)
    eq(e.response['Error']['Message'], 'Not Modified')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-None-Match: bogus ETag')
@attr(assertion='succeeds')
def test_get_object_ifnonematch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo', IfNoneMatch='ABCORZ')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Modified-Since: before')
@attr(assertion='succeeds')
def test_get_object_ifmodifiedsince_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo', IfModifiedSince='Sat, 29 Oct 1994 19:43:31 GMT')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Modified-Since: after')
@attr(assertion='fails 304')
def test_get_object_ifmodifiedsince_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    response = client.get_object(Bucket=bucket_name, Key='foo')
    last_modified = str(response['LastModified'])

    last_modified = last_modified.split('+')[0]
    mtime = datetime.datetime.strptime(last_modified, '%Y-%m-%d %H:%M:%S')

    after = mtime + datetime.timedelta(seconds=1)
    after_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", after.timetuple())

    time.sleep(1)

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfModifiedSince=after_str)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 304)
    eq(e.response['Error']['Message'], 'Not Modified')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Unmodified-Since: before')
@attr(assertion='fails 412')
def test_get_object_ifunmodifiedsince_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo', IfUnmodifiedSince='Sat, 29 Oct 1994 19:43:31 GMT')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Unmodified-Since: after')
@attr(assertion='succeeds')
def test_get_object_ifunmodifiedsince_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo', IfUnmodifiedSince='Sat, 29 Oct 2100 19:43:31 GMT')
    body = _get_body(response)
    eq(body, 'bar')


@attr(resource='object')
@attr(method='put')
@attr(operation='data re-write w/ If-Match: the latest ETag')
@attr(assertion='replaces previous data and metadata')
@attr('fails_on_aws')
def test_put_object_ifmatch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    etag = response['ETag'].replace('"', '')

    # pass in custom header 'If-Match' before PutObject call
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': etag}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    response = client.put_object(Bucket=bucket_name,Key='foo', Body='zar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'zar')

@attr(resource='object')
@attr(method='get')
@attr(operation='get w/ If-Match: bogus ETag')
@attr(assertion='fails 412')
def test_put_object_ifmatch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    # pass in custom header 'If-Match' before PutObject call
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': '"ABCORZ"'}))
    client.meta.events.register('before-call.s3.PutObject', lf)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='foo', Body='zar')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='put')
@attr(operation='overwrite existing object w/ If-Match: *')
@attr(assertion='replaces previous data and metadata')
@attr('fails_on_aws')
def test_put_object_ifmatch_overwrite_existed_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': '*'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    response = client.put_object(Bucket=bucket_name,Key='foo', Body='zar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'zar')

@attr(resource='object')
@attr(method='put')
@attr(operation='overwrite non-existing object w/ If-Match: *')
@attr(assertion='fails 412')
@attr('fails_on_aws')
def test_put_object_ifmatch_nonexisted_failed():
    bucket_name = get_new_bucket()
    client = get_client()

    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': '*'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='foo', Body='bar')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

@attr(resource='object')
@attr(method='put')
@attr(operation='overwrite existing object w/ If-None-Match: outdated ETag')
@attr(assertion='replaces previous data and metadata')
@attr('fails_on_aws')
def test_put_object_ifnonmatch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-None-Match': 'ABCORZ'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    response = client.put_object(Bucket=bucket_name,Key='foo', Body='zar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'zar')

@attr(resource='object')
@attr(method='put')
@attr(operation='overwrite existing object w/ If-None-Match: the latest ETag')
@attr(assertion='fails 412')
@attr('fails_on_aws')
def test_put_object_ifnonmatch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    etag = response['ETag'].replace('"', '')

    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-None-Match': etag}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='foo', Body='zar')

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='put')
@attr(operation='overwrite non-existing object w/ If-None-Match: *')
@attr(assertion='succeeds')
@attr('fails_on_aws')
def test_put_object_ifnonmatch_nonexisted_good():
    bucket_name = get_new_bucket()
    client = get_client()

    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-None-Match': '*'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='put')
@attr(operation='overwrite existing object w/ If-None-Match: *')
@attr(assertion='fails 412')
@attr('fails_on_aws')
def test_put_object_ifnonmatch_overwrite_existed_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-None-Match': '*'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='foo', Body='zar')

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

def _setup_bucket_object_acl(bucket_acl, object_acl):
    """
    add a foo key, and specified key and bucket acls to
    a (new or existing) bucket.
    """
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL=bucket_acl, Bucket=bucket_name)
    client.put_object(ACL=object_acl, Bucket=bucket_name, Key='foo')

    return bucket_name

def _setup_bucket_acl(bucket_acl=None):
    """
    set up a new bucket with specified acl
    """
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(ACL=bucket_acl, Bucket=bucket_name)

    return bucket_name

def add_bucket_user_grant(bucket_name, grant):
    """
    Adds a grant to the existing grants meant to be passed into
    the AccessControlPolicy argument of put_object_acls for an object
    owned by the main user, not the alt user
    A grant is a dictionary in the form of:
    {u'Grantee': {u'Type': 'type', u'DisplayName': 'name', u'ID': 'id'}, u'Permission': 'PERM'}
    """
    client = get_client()
    main_user_id = get_main_user_id()
    main_display_name = get_main_display_name()

    response = client.get_bucket_acl(Bucket=bucket_name)

    grants = response['Grants']
    grants.append(grant)

    grant = {'Grants': grants, 'Owner': {'DisplayName': main_display_name, 'ID': main_user_id}}

    return grant

def _check_object_acl(permission):
    """
    Sets the permission on an object then checks to see
    if it was set
    """
    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.get_object_acl(Bucket=bucket_name, Key='foo')

    policy = {}
    policy['Owner'] = response['Owner']
    policy['Grants'] = response['Grants']
    policy['Grants'][0]['Permission'] = permission

    client.put_object_acl(Bucket=bucket_name, Key='foo', AccessControlPolicy=policy)

    response = client.get_object_acl(Bucket=bucket_name, Key='foo')
    grants = response['Grants']

    main_user_id = get_main_user_id()
    main_display_name = get_main_display_name()

    check_grants(
        grants,
        [
            dict(
                Permission=permission,
                ID=main_user_id,
                DisplayName=main_display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )



def _bucket_acl_grant_userid(permission):
    """
    create a new bucket, grant a specific user the specified
    permission, read back the acl and verify correct setting
    """
    bucket_name = get_new_bucket()
    client = get_client()

    main_user_id = get_main_user_id()
    main_display_name = get_main_display_name()

    alt_user_id = get_alt_user_id()
    alt_display_name = get_alt_display_name()

    grant = {'Grantee': {'ID': alt_user_id, 'Type': 'CanonicalUser' }, 'Permission': permission}

    grant = add_bucket_user_grant(bucket_name, grant)

    client.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=grant)

    response = client.get_bucket_acl(Bucket=bucket_name)

    grants = response['Grants']
    check_grants(
        grants,
        [
            dict(
                Permission=permission,
                ID=alt_user_id,
                DisplayName=alt_display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            dict(
                Permission='FULL_CONTROL',
                ID=main_user_id,
                DisplayName=main_display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ],
        )

    return bucket_name

def _check_bucket_acl_grant_can_read(bucket_name):
    """
    verify ability to read the specified bucket
    """
    alt_client = get_alt_client()
    response = alt_client.head_bucket(Bucket=bucket_name)

def _check_bucket_acl_grant_cant_read(bucket_name):
    """
    verify inability to read the specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.head_bucket, Bucket=bucket_name)

def _check_bucket_acl_grant_can_readacp(bucket_name):
    """
    verify ability to read acls on specified bucket
    """
    alt_client = get_alt_client()
    alt_client.get_bucket_acl(Bucket=bucket_name)

def _check_bucket_acl_grant_cant_readacp(bucket_name):
    """
    verify inability to read acls on specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.get_bucket_acl, Bucket=bucket_name)

def _check_bucket_acl_grant_can_write(bucket_name):
    """
    verify ability to write the specified bucket
    """
    alt_client = get_alt_client()
    alt_client.put_object(Bucket=bucket_name, Key='foo-write', Body='bar')

def _check_bucket_acl_grant_cant_write(bucket_name):

    """
    verify inability to write the specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key='foo-write', Body='bar')

def _check_bucket_acl_grant_can_writeacp(bucket_name):
    """
    verify ability to set acls on the specified bucket
    """
    alt_client = get_alt_client()
    alt_client.put_bucket_acl(Bucket=bucket_name, ACL='public-read')

def _check_bucket_acl_grant_cant_writeacp(bucket_name):
    """
    verify inability to set acls on the specified bucket
    """
    alt_client = get_alt_client()
    check_access_denied(alt_client.put_bucket_acl,Bucket=bucket_name, ACL='public-read')


def _get_acl_header(user_id=None, perms=None):
    all_headers = ["read", "write", "read-acp", "write-acp", "full-control"]
    headers = []

    if user_id == None:
        user_id = get_alt_user_id()

    if perms != None:
        for perm in perms:
            header = ("x-amz-grant-{perm}".format(perm=perm), "id={uid}".format(uid=user_id))
            headers.append(header)

    else:
        for perm in all_headers:
            header = ("x-amz-grant-{perm}".format(perm=perm), "id={uid}".format(uid=user_id))
            headers.append(header)

    return headers


# TODO rgw log_bucket.set_as_logging_target() gives 403 Forbidden
# http://tracker.newdream.net/issues/984
@attr(resource='bucket.log')
@attr(method='put')
@attr(operation='set/enable/disable logging target')
@attr(assertion='operations succeed')
@attr('fails_on_rgw')
def test_logging_toggle():
    bucket_name = get_new_bucket()
    client = get_client()

    main_display_name = get_main_display_name()
    main_user_id = get_main_user_id()

    status = {'LoggingEnabled': {'TargetBucket': bucket_name, 'TargetGrants': [{'Grantee': {'DisplayName': main_display_name, 'ID': main_user_id,'Type': 'CanonicalUser'},'Permission': 'FULL_CONTROL'}], 'TargetPrefix': 'foologgingprefix'}}

    client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus=status)
    client.get_bucket_logging(Bucket=bucket_name)
    status = {'LoggingEnabled': {}}
    client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus=status)
    # NOTE: this does not actually test whether or not logging works

def _setup_access(bucket_acl, object_acl):
    """
    Simple test fixture: create a bucket with given ACL, with objects:
    - a: owning user, given ACL
    - a2: same object accessed by some other user
    - b: owning user, default ACL in bucket w/given ACL
    - b2: same object accessed by a some other user
    """
    bucket_name = get_new_bucket()
    client = get_client()

    key1 = 'foo'
    key2 = 'bar'
    newkey = 'new'

    client.put_bucket_acl(Bucket=bucket_name, ACL=bucket_acl)
    client.put_object(Bucket=bucket_name, Key=key1, Body='foocontent')
    client.put_object_acl(Bucket=bucket_name, Key=key1, ACL=object_acl)
    client.put_object(Bucket=bucket_name, Key=key2, Body='barcontent')

    return bucket_name, key1, key2, newkey

def get_bucket_key_names(bucket_name):
    objs_list = get_objects_list(bucket_name)
    return frozenset(obj for obj in objs_list)

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: private/private')
@attr(assertion='public has no access to bucket or objects')
def test_access_bucket_private_object_private():
    # all the test_access_* tests follow this template
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='private', object_acl='private')

    alt_client = get_alt_client()
    # acled object read fail
    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key1)
    # default object read fail
    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key2)
    # bucket read fail
    check_access_denied(alt_client.list_objects, Bucket=bucket_name)

    # acled object write fail
    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='barcontent')
    # NOTE: The above put's causes the connection to go bad, therefore the client can't be used
    # anymore. This can be solved either by:
    # 1) putting an empty string ('') in the 'Body' field of those put_object calls
    # 2) getting a new client hence the creation of alt_client{2,3} for the tests below
    # TODO: Test it from another host and on AWS, Report this to Amazon, if findings are identical

    alt_client2 = get_alt_client()
    # default object write fail
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')
    # bucket write fail
    alt_client3 = get_alt_client()
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: private/private with list-objects-v2')
@attr(assertion='public has no access to bucket or objects')
@attr('list-objects-v2')
def test_access_bucket_private_objectv2_private():
    # all the test_access_* tests follow this template
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='private', object_acl='private')

    alt_client = get_alt_client()
    # acled object read fail
    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key1)
    # default object read fail
    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key2)
    # bucket read fail
    check_access_denied(alt_client.list_objects_v2, Bucket=bucket_name)

    # acled object write fail
    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='barcontent')
    # NOTE: The above put's causes the connection to go bad, therefore the client can't be used
    # anymore. This can be solved either by:
    # 1) putting an empty string ('') in the 'Body' field of those put_object calls
    # 2) getting a new client hence the creation of alt_client{2,3} for the tests below
    # TODO: Test it from another host and on AWS, Report this to Amazon, if findings are identical

    alt_client2 = get_alt_client()
    # default object write fail
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')
    # bucket write fail
    alt_client3 = get_alt_client()
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: private/public-read')
@attr(assertion='public can only read readable object')
def test_access_bucket_private_object_publicread():

    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='private', object_acl='public-read')
    alt_client = get_alt_client()
    response = alt_client.get_object(Bucket=bucket_name, Key=key1)

    body = _get_body(response)

    # a should be public-read, b gets default (private)
    eq(body, 'foocontent')

    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='foooverwrite')
    alt_client2 = get_alt_client()
    check_access_denied(alt_client2.get_object, Bucket=bucket_name, Key=key2)
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')

    alt_client3 = get_alt_client()
    check_access_denied(alt_client3.list_objects, Bucket=bucket_name)
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: private/public-read with list-objects-v2')
@attr(assertion='public can only read readable object')
@attr('list-objects-v2')
def test_access_bucket_private_objectv2_publicread():

    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='private', object_acl='public-read')
    alt_client = get_alt_client()
    response = alt_client.get_object(Bucket=bucket_name, Key=key1)

    body = _get_body(response)

    # a should be public-read, b gets default (private)
    eq(body, 'foocontent')

    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='foooverwrite')
    alt_client2 = get_alt_client()
    check_access_denied(alt_client2.get_object, Bucket=bucket_name, Key=key2)
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')

    alt_client3 = get_alt_client()
    check_access_denied(alt_client3.list_objects_v2, Bucket=bucket_name)
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: private/public-read/write')
@attr(assertion='public can only read the readable object')
def test_access_bucket_private_object_publicreadwrite():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='private', object_acl='public-read-write')
    alt_client = get_alt_client()
    response = alt_client.get_object(Bucket=bucket_name, Key=key1)

    body = _get_body(response)

    # a should be public-read-only ... because it is in a private bucket
    # b gets default (private)
    eq(body, 'foocontent')

    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='foooverwrite')
    alt_client2 = get_alt_client()
    check_access_denied(alt_client2.get_object, Bucket=bucket_name, Key=key2)
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')

    alt_client3 = get_alt_client()
    check_access_denied(alt_client3.list_objects, Bucket=bucket_name)
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: private/public-read/write with list-objects-v2')
@attr(assertion='public can only read the readable object')
@attr('list-objects-v2')
def test_access_bucket_private_objectv2_publicreadwrite():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='private', object_acl='public-read-write')
    alt_client = get_alt_client()
    response = alt_client.get_object(Bucket=bucket_name, Key=key1)

    body = _get_body(response)

    # a should be public-read-only ... because it is in a private bucket
    # b gets default (private)
    eq(body, 'foocontent')

    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='foooverwrite')
    alt_client2 = get_alt_client()
    check_access_denied(alt_client2.get_object, Bucket=bucket_name, Key=key2)
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')

    alt_client3 = get_alt_client()
    check_access_denied(alt_client3.list_objects_v2, Bucket=bucket_name)
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: public-read/private')
@attr(assertion='public can only list the bucket')
def test_access_bucket_publicread_object_private():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='public-read', object_acl='private')
    alt_client = get_alt_client()

    # a should be private, b gets default (private)
    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key1)
    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='barcontent')

    alt_client2 = get_alt_client()
    check_access_denied(alt_client2.get_object, Bucket=bucket_name, Key=key2)
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')

    alt_client3 = get_alt_client()

    objs = get_objects_list(bucket=bucket_name, client=alt_client3)

    eq(objs, ['bar', 'foo'])
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: public-read/public-read')
@attr(assertion='public can read readable objects and list bucket')
def test_access_bucket_publicread_object_publicread():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='public-read', object_acl='public-read')
    alt_client = get_alt_client()

    response = alt_client.get_object(Bucket=bucket_name, Key=key1)

    # a should be public-read, b gets default (private)
    body = _get_body(response)
    eq(body, 'foocontent')

    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='foooverwrite')

    alt_client2 = get_alt_client()
    check_access_denied(alt_client2.get_object, Bucket=bucket_name, Key=key2)
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')

    alt_client3 = get_alt_client()

    objs = get_objects_list(bucket=bucket_name, client=alt_client3)

    eq(objs, ['bar', 'foo'])
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')


@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: public-read/public-read-write')
@attr(assertion='public can read readable objects and list bucket')
def test_access_bucket_publicread_object_publicreadwrite():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='public-read', object_acl='public-read-write')
    alt_client = get_alt_client()

    response = alt_client.get_object(Bucket=bucket_name, Key=key1)

    body = _get_body(response)

    # a should be public-read-only ... because it is in a r/o bucket
    # b gets default (private)
    eq(body, 'foocontent')

    check_access_denied(alt_client.put_object, Bucket=bucket_name, Key=key1, Body='foooverwrite')

    alt_client2 = get_alt_client()
    check_access_denied(alt_client2.get_object, Bucket=bucket_name, Key=key2)
    check_access_denied(alt_client2.put_object, Bucket=bucket_name, Key=key2, Body='baroverwrite')

    alt_client3 = get_alt_client()

    objs = get_objects_list(bucket=bucket_name, client=alt_client3)

    eq(objs, ['bar', 'foo'])
    check_access_denied(alt_client3.put_object, Bucket=bucket_name, Key=newkey, Body='newcontent')


@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: public-read-write/private')
@attr(assertion='private objects cannot be read, but can be overwritten')
def test_access_bucket_publicreadwrite_object_private():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='public-read-write', object_acl='private')
    alt_client = get_alt_client()

    # a should be private, b gets default (private)
    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key1)
    alt_client.put_object(Bucket=bucket_name, Key=key1, Body='barcontent')

    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key2)
    alt_client.put_object(Bucket=bucket_name, Key=key2, Body='baroverwrite')

    objs = get_objects_list(bucket=bucket_name, client=alt_client)
    eq(objs, ['bar', 'foo'])
    alt_client.put_object(Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: public-read-write/public-read')
@attr(assertion='private objects cannot be read, but can be overwritten')
def test_access_bucket_publicreadwrite_object_publicread():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='public-read-write', object_acl='public-read')
    alt_client = get_alt_client()

    # a should be public-read, b gets default (private)
    response = alt_client.get_object(Bucket=bucket_name, Key=key1)

    body = _get_body(response)
    eq(body, 'foocontent')
    alt_client.put_object(Bucket=bucket_name, Key=key1, Body='barcontent')

    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key2)
    alt_client.put_object(Bucket=bucket_name, Key=key2, Body='baroverwrite')

    objs = get_objects_list(bucket=bucket_name, client=alt_client)
    eq(objs, ['bar', 'foo'])
    alt_client.put_object(Bucket=bucket_name, Key=newkey, Body='newcontent')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='set bucket/object acls: public-read-write/public-read-write')
@attr(assertion='private objects cannot be read, but can be overwritten')
def test_access_bucket_publicreadwrite_object_publicreadwrite():
    bucket_name, key1, key2, newkey = _setup_access(bucket_acl='public-read-write', object_acl='public-read-write')
    alt_client = get_alt_client()
    response = alt_client.get_object(Bucket=bucket_name, Key=key1)
    body = _get_body(response)

    # a should be public-read-write, b gets default (private)
    eq(body, 'foocontent')
    alt_client.put_object(Bucket=bucket_name, Key=key1, Body='foooverwrite')
    check_access_denied(alt_client.get_object, Bucket=bucket_name, Key=key2)
    alt_client.put_object(Bucket=bucket_name, Key=key2, Body='baroverwrite')
    objs = get_objects_list(bucket=bucket_name, client=alt_client)
    eq(objs, ['bar', 'foo'])
    alt_client.put_object(Bucket=bucket_name, Key=newkey, Body='newcontent')

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


def _multipart_upload(bucket_name, key, size, part_size=5*1024*1024, client=None, content_type=None, metadata=None, resend_parts=[]):
    """
    generate a multi-part upload for a random file of specifed size,
    if requested, generate a list of the parts
    return the upload descriptor
    """
    if client == None:
        client = get_client()


    if content_type == None and metadata == None:
        response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    else:
        response = client.create_multipart_upload(Bucket=bucket_name, Key=key, Metadata=metadata, ContentType=content_type)

    upload_id = response['UploadId']
    s = ''
    parts = []
    for i, part in enumerate(generate_random(size, part_size)):
        # part_num is necessary because PartNumber for upload_part and in parts must start at 1 and i starts at 0
        part_num = i+1
        s += part
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num, Body=part)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': part_num})
        if i in resend_parts:
            client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num, Body=part)

    return (upload_id, s, parts)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart upload without parts')
def test_multipart_upload_empty():
    bucket_name = get_new_bucket()
    client = get_client()

    key1 = "mymultipart"
    objlen = 0
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key1, size=objlen)
    e = assert_raises(ClientError, client.complete_multipart_upload,Bucket=bucket_name, Key=key1, UploadId=upload_id)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'MalformedXML')

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart uploads with single small part')
def test_multipart_upload_small():
    bucket_name = get_new_bucket()
    client = get_client()

    key1 = "mymultipart"
    objlen = 1
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key1, size=objlen)
    response = client.complete_multipart_upload(Bucket=bucket_name, Key=key1, UploadId=upload_id, MultipartUpload={'Parts': parts})
    response = client.get_object(Bucket=bucket_name, Key=key1)
    eq(response['ContentLength'], objlen)

def _create_key_with_random_content(keyname, size=7*1024*1024, bucket_name=None, client=None):
    if bucket_name is None:
        bucket_name = get_new_bucket()

    if client == None:
        client = get_client()

    data_str = str(next(generate_random(size, size)))
    data = bytes(data_str, 'utf-8')
    client.put_object(Bucket=bucket_name, Key=keyname, Body=data)

    return bucket_name

def _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size, client=None, part_size=5*1024*1024, version_id=None):

    if(client == None):
        client = get_client()

    response = client.create_multipart_upload(Bucket=dest_bucket_name, Key=dest_key)
    upload_id = response['UploadId']

    if(version_id == None):
        copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    else:
        copy_source = {'Bucket': src_bucket_name, 'Key': src_key, 'VersionId': version_id}

    parts = []

    i = 0
    for start_offset in range(0, size, part_size):
        end_offset = min(start_offset + part_size - 1, size - 1)
        part_num = i+1
        copy_source_range = 'bytes={start}-{end}'.format(start=start_offset, end=end_offset)
        response = client.upload_part_copy(Bucket=dest_bucket_name, Key=dest_key, CopySource=copy_source, PartNumber=part_num, UploadId=upload_id, CopySourceRange=copy_source_range)
        parts.append({'ETag': response['CopyPartResult']['ETag'], 'PartNumber': part_num})
        i = i+1

    return (upload_id, parts)

def _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name, version_id=None):
    client = get_client()

    if(version_id == None):
        response = client.get_object(Bucket=src_bucket_name, Key=src_key)
    else:
        response = client.get_object(Bucket=src_bucket_name, Key=src_key, VersionId=version_id)
    src_size = response['ContentLength']

    response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
    dest_size = response['ContentLength']
    dest_data = _get_body(response)
    assert(src_size >= dest_size)

    r = 'bytes={s}-{e}'.format(s=0, e=dest_size-1)
    if(version_id == None):
        response = client.get_object(Bucket=src_bucket_name, Key=src_key, Range=r)
    else:
        response = client.get_object(Bucket=src_bucket_name, Key=src_key, Range=r, VersionId=version_id)
    src_data = _get_body(response)
    eq(src_data, dest_data)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies with single small part')
def test_multipart_copy_small():
    src_key = 'foo'
    src_bucket_name = _create_key_with_random_content(src_key)

    dest_bucket_name = get_new_bucket()
    dest_key = "mymultipart"
    size = 1
    client = get_client()

    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
    eq(size, response['ContentLength'])
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies with an invalid range')
def test_multipart_copy_invalid_range():
    client = get_client()
    src_key = 'source'
    src_bucket_name = _create_key_with_random_content(src_key, size=5)

    response = client.create_multipart_upload(Bucket=src_bucket_name, Key='dest')
    upload_id = response['UploadId']

    copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    copy_source_range = 'bytes={start}-{end}'.format(start=0, end=21)

    e = assert_raises(ClientError, client.upload_part_copy,Bucket=src_bucket_name, Key='dest', UploadId=upload_id, CopySource=copy_source, CopySourceRange=copy_source_range, PartNumber=1)
    status, error_code = _get_status_and_error_code(e.response)
    valid_status = [400, 416]
    if not status in valid_status:
       raise AssertionError("Invalid response " + str(status))
    eq(error_code, 'InvalidRange')


@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copy with an improperly formatted range')
# TODO: remove fails_on_rgw when https://tracker.ceph.com/issues/40795 is resolved
@attr('fails_on_rgw')
def test_multipart_copy_improper_range():
    client = get_client()
    src_key = 'source'
    src_bucket_name = _create_key_with_random_content(src_key, size=5)

    response = client.create_multipart_upload(
        Bucket=src_bucket_name, Key='dest')
    upload_id = response['UploadId']

    copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    test_ranges = ['{start}-{end}'.format(start=0, end=2),
                   'bytes={start}'.format(start=0),
                   'bytes=hello-world',
                   'bytes=0-bar',
                   'bytes=hello-',
                   'bytes=0-2,3-5']

    for test_range in test_ranges:
        e = assert_raises(ClientError, client.upload_part_copy,
                          Bucket=src_bucket_name, Key='dest',
                          UploadId=upload_id,
                          CopySource=copy_source,
                          CopySourceRange=test_range,
                          PartNumber=1)
        status, error_code = _get_status_and_error_code(e.response)
        eq(status, 400)
        eq(error_code, 'InvalidArgument')


@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies without x-amz-copy-source-range')
def test_multipart_copy_without_range():
    client = get_client()
    src_key = 'source'
    src_bucket_name = _create_key_with_random_content(src_key, size=10)
    dest_bucket_name = get_new_bucket_name()
    get_new_bucket(name=dest_bucket_name)
    dest_key = "mymultipartcopy"

    response = client.create_multipart_upload(Bucket=dest_bucket_name, Key=dest_key)
    upload_id = response['UploadId']
    parts = []

    copy_source = {'Bucket': src_bucket_name, 'Key': src_key}
    part_num = 1
    copy_source_range = 'bytes={start}-{end}'.format(start=0, end=9)

    response = client.upload_part_copy(Bucket=dest_bucket_name, Key=dest_key, CopySource=copy_source, PartNumber=part_num, UploadId=upload_id)

    parts.append({'ETag': response['CopyPartResult']['ETag'], 'PartNumber': part_num})
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
    eq(response['ContentLength'], 10)
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

@attr(resource='object')
@attr(method='put')
@attr(operation='check multipart copies with single small part')
def test_multipart_copy_special_names():
    src_bucket_name = get_new_bucket()

    dest_bucket_name = get_new_bucket()

    dest_key = "mymultipart"
    size = 1
    client = get_client()

    for src_key in (' ', '_', '__', '?versionId'):
        _create_key_with_random_content(src_key, bucket_name=src_bucket_name)
        (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
        response = client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
        response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
        eq(size, response['ContentLength'])
        _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

def _check_content_using_range(key, bucket_name, data, step):
    client = get_client()
    response = client.get_object(Bucket=bucket_name, Key=key)
    size = response['ContentLength']

    for ofs in range(0, size, step):
        toread = size - ofs
        if toread > step:
            toread = step
        end = ofs + toread - 1
        r = 'bytes={s}-{e}'.format(s=ofs, e=end)
        response = client.get_object(Bucket=bucket_name, Key=key, Range=r)
        eq(response['ContentLength'], toread)
        body = _get_body(response)
        eq(body, data[ofs:end+1])

@attr(resource='object')
@attr(method='put')
@attr(operation='complete multi-part upload')
@attr(assertion='successful')
@attr('fails_on_aws')
def test_multipart_upload():
    bucket_name = get_new_bucket()
    key="mymultipart"
    content_type='text/bla'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    client = get_client()

    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen, content_type=content_type, metadata=metadata)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.head_bucket(Bucket=bucket_name)
    rgw_bytes_used = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-bytes-used', objlen))
    eq(rgw_bytes_used, objlen)

    rgw_object_count = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-object-count', 1))
    eq(rgw_object_count, 1)

    response = client.get_object(Bucket=bucket_name, Key=key)
    eq(response['ContentType'], content_type)
    eq(response['Metadata'], metadata)
    body = _get_body(response)
    eq(len(body), response['ContentLength'])
    eq(body, data)

    _check_content_using_range(key, bucket_name, data, 1000000)
    _check_content_using_range(key, bucket_name, data, 10000000)

def check_versioning(bucket_name, status):
    client = get_client()

    try:
        response = client.get_bucket_versioning(Bucket=bucket_name)
        eq(response['Status'], status)
    except KeyError:
        eq(status, None)

# amazon is eventual consistent, retry a bit if failed
def check_configure_versioning_retry(bucket_name, status, expected_string):
    client = get_client()
    client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'Status': status})

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
@attr(method='put')
@attr(operation='check multipart copies of versioned objects')
@attr('versioning')
def test_multipart_copy_versioned():
    src_bucket_name = get_new_bucket()
    dest_bucket_name = get_new_bucket()

    dest_key = "mymultipart"
    check_versioning(src_bucket_name, None)

    src_key = 'foo'
    check_configure_versioning_retry(src_bucket_name, "Enabled", "Enabled")

    size = 15 * 1024 * 1024
    _create_key_with_random_content(src_key, size=size, bucket_name=src_bucket_name)
    _create_key_with_random_content(src_key, size=size, bucket_name=src_bucket_name)
    _create_key_with_random_content(src_key, size=size, bucket_name=src_bucket_name)

    version_id = []
    client = get_client()
    response = client.list_object_versions(Bucket=src_bucket_name)
    for ver in response['Versions']:
        version_id.append(ver['VersionId'])

    for vid in version_id:
        (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size, version_id=vid)
        response = client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
        response = client.get_object(Bucket=dest_bucket_name, Key=dest_key)
        eq(size, response['ContentLength'])
        _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name, version_id=vid)

def _check_upload_multipart_resend(bucket_name, key, objlen, resend_parts):
    content_type = 'text/bla'
    metadata = {'foo': 'bar'}
    client = get_client()
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen, content_type=content_type, metadata=metadata, resend_parts=resend_parts)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=bucket_name, Key=key)
    eq(response['ContentType'], content_type)
    eq(response['Metadata'], metadata)
    body = _get_body(response)
    eq(len(body), response['ContentLength'])
    eq(body, data)

    _check_content_using_range(key, bucket_name, data, 1000000)
    _check_content_using_range(key, bucket_name, data, 10000000)

@attr(resource='object')
@attr(method='put')
@attr(operation='complete multiple multi-part upload with different sizes')
@attr(resource='object')
@attr(method='put')
@attr(operation='complete multi-part upload')
@attr(assertion='successful')
def test_multipart_upload_resend_part():
    bucket_name = get_new_bucket()
    key="mymultipart"
    objlen = 30 * 1024 * 1024

    _check_upload_multipart_resend(bucket_name, key, objlen, [0])
    _check_upload_multipart_resend(bucket_name, key, objlen, [1])
    _check_upload_multipart_resend(bucket_name, key, objlen, [2])
    _check_upload_multipart_resend(bucket_name, key, objlen, [1,2])
    _check_upload_multipart_resend(bucket_name, key, objlen, [0,1,2,3,4,5])

@attr(assertion='successful')
def test_multipart_upload_multiple_sizes():
    bucket_name = get_new_bucket()
    key="mymultipart"
    client = get_client()

    objlen = 5*1024*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 5*1024*1024+100*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 5*1024*1024+600*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 10*1024*1024+100*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 10*1024*1024+600*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    objlen = 10*1024*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

@attr(assertion='successful')
def test_multipart_copy_multiple_sizes():
    src_key = 'foo'
    src_bucket_name = _create_key_with_random_content(src_key, 12*1024*1024)

    dest_bucket_name = get_new_bucket()
    dest_key="mymultipart"
    client = get_client()

    size = 5*1024*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 5*1024*1024+100*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 5*1024*1024+600*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 10*1024*1024+100*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 10*1024*1024+600*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

    size = 10*1024*1024
    (upload_id, parts) = _multipart_copy(src_bucket_name, src_key, dest_bucket_name, dest_key, size)
    client.complete_multipart_upload(Bucket=dest_bucket_name, Key=dest_key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    _check_key_content(src_key, src_bucket_name, dest_key, dest_bucket_name)

@attr(resource='object')
@attr(method='put')
@attr(operation='check failure on multiple multi-part upload with size too small')
@attr(assertion='fails 400')
def test_multipart_upload_size_too_small():
    bucket_name = get_new_bucket()
    key="mymultipart"
    client = get_client()

    size = 100*1024
    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=size, part_size=10*1024)
    e = assert_raises(ClientError, client.complete_multipart_upload, Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'EntityTooSmall')

def gen_rand_string(size, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def _do_test_multipart_upload_contents(bucket_name, key, num_parts):
    payload=gen_rand_string(5)*1024*1024
    client = get_client()

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []

    for part_num in range(0, num_parts):
        part = bytes(payload, 'utf-8')
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num+1, Body=part)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': part_num+1})

    last_payload = '123'*1024*1024
    last_part = bytes(last_payload, 'utf-8')
    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=num_parts+1, Body=last_part)
    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': num_parts+1})

    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=bucket_name, Key=key)
    test_string = _get_body(response)

    all_payload = payload*num_parts + last_payload

    assert test_string == all_payload

    return all_payload

@attr(resource='object')
@attr(method='put')
@attr(operation='check contents of multi-part upload')
@attr(assertion='successful')
def test_multipart_upload_contents():
    bucket_name = get_new_bucket()
    _do_test_multipart_upload_contents(bucket_name, 'mymultipart', 3)

@attr(resource='object')
@attr(method='put')
@attr(operation=' multi-part upload overwrites existing key')
@attr(assertion='successful')
def test_multipart_upload_overwrite_existing_object():
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'mymultipart'
    payload='12345'*1024*1024
    num_parts=2
    client.put_object(Bucket=bucket_name, Key=key, Body=payload)


    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []

    for part_num in range(0, num_parts):
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num+1, Body=payload)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': part_num+1})

    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.get_object(Bucket=bucket_name, Key=key)
    test_string = _get_body(response)

    assert test_string == payload*num_parts

@attr(resource='object')
@attr(method='put')
@attr(operation='abort multi-part upload')
@attr(assertion='successful')
def test_abort_multipart_upload():
    bucket_name = get_new_bucket()
    key="mymultipart"
    objlen = 10 * 1024 * 1024
    client = get_client()

    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen)
    client.abort_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id)

    response = client.head_bucket(Bucket=bucket_name)
    rgw_bytes_used = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-bytes-used', 0))
    eq(rgw_bytes_used, 0)

    rgw_object_count = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-object-count', 0))
    eq(rgw_object_count, 0)

@attr(resource='object')
@attr(method='put')
@attr(operation='abort non-existent multi-part upload')
@attr(assertion='fails 404')
def test_abort_multipart_upload_not_found():
    bucket_name = get_new_bucket()
    client = get_client()
    key="mymultipart"
    client.put_object(Bucket=bucket_name, Key=key)

    e = assert_raises(ClientError, client.abort_multipart_upload, Bucket=bucket_name, Key=key, UploadId='56788')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchUpload')

@attr(resource='object')
@attr(method='put')
@attr(operation='concurrent multi-part uploads')
@attr(assertion='successful')
def test_list_multipart_upload():
    bucket_name = get_new_bucket()
    client = get_client()
    key="mymultipart"
    mb = 1024 * 1024

    upload_ids = []
    (upload_id1, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=5*mb)
    upload_ids.append(upload_id1)
    (upload_id2, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=6*mb)
    upload_ids.append(upload_id2)

    key2="mymultipart2"
    (upload_id3, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key2, size=5*mb)
    upload_ids.append(upload_id3)

    response = client.list_multipart_uploads(Bucket=bucket_name)
    uploads = response['Uploads']
    resp_uploadids = []

    for i in range(0, len(uploads)):
        resp_uploadids.append(uploads[i]['UploadId'])

    for i in range(0, len(upload_ids)):
        eq(True, (upload_ids[i] in resp_uploadids))

    client.abort_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id1)
    client.abort_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id2)
    client.abort_multipart_upload(Bucket=bucket_name, Key=key2, UploadId=upload_id3)

@attr(resource='object')
@attr(method='put')
@attr(operation='multi-part upload with missing part')
def test_multipart_upload_missing_part():
    bucket_name = get_new_bucket()
    client = get_client()
    key="mymultipart"
    size = 1

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []
    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=1, Body=bytes('\x00', 'utf-8'))
    # 'PartNumber should be 1'
    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 9999})

    e = assert_raises(ClientError, client.complete_multipart_upload, Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidPart')

@attr(resource='object')
@attr(method='put')
@attr(operation='multi-part upload with incorrect ETag')
def test_multipart_upload_incorrect_etag():
    bucket_name = get_new_bucket()
    client = get_client()
    key="mymultipart"
    size = 1

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    upload_id = response['UploadId']

    parts = []
    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=1, Body=bytes('\x00', 'utf-8'))
    # 'ETag' should be "93b885adfe0da089cdf634904fd59f71"
    parts.append({'ETag': "ffffffffffffffffffffffffffffffff", 'PartNumber': 1})

    e = assert_raises(ClientError, client.complete_multipart_upload, Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidPart')

def _simple_http_req_100_cont(host, port, is_secure, method, resource):
    """
    Send the specified request w/expect 100-continue
    and await confirmation.
    """
    req_str = '{method} {resource} HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: identity\r\nContent-Length: 123\r\nExpect: 100-continue\r\n\r\n'.format(
            method=method,
            resource=resource,
            host=host,
            )

    req = bytes(req_str, 'utf-8')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if is_secure:
        s = ssl.wrap_socket(s);
    s.settimeout(5)
    s.connect((host, port))
    s.send(req)

    try:
        data = s.recv(1024)
    except socket.error as msg:
        print('got response: ', msg)
        print('most likely server doesn\'t support 100-continue')

    s.close()
    data_str = data.decode()
    l = data_str.split(' ')

    assert l[0].startswith('HTTP')

    return l[1]

@attr(resource='object')
@attr(method='put')
@attr(operation='w/expect continue')
@attr(assertion='succeeds if object is public-read-write')
@attr('100_continue')
@attr('fails_on_mod_proxy_fcgi')
def test_100_continue():
    bucket_name = get_new_bucket_name()
    client = get_client()
    client.create_bucket(Bucket=bucket_name)
    objname='testobj'
    resource = '/{bucket}/{obj}'.format(bucket=bucket_name, obj=objname)

    host = get_config_host()
    port = get_config_port()
    is_secure = get_config_is_secure()

    #NOTES: this test needs to be tested when is_secure is True
    status = _simple_http_req_100_cont(host, port, is_secure, 'PUT', resource)
    eq(status, '403')

    client.put_bucket_acl(Bucket=bucket_name, ACL='public-read-write')

    status = _simple_http_req_100_cont(host, port, is_secure, 'PUT', resource)
    eq(status, '100')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set cors')
@attr(assertion='succeeds')
@attr('cors')
def test_set_cors():
    bucket_name = get_new_bucket()
    client = get_client()
    allowed_methods = ['GET', 'PUT']
    allowed_origins = ['*.get', '*.put']

    cors_config ={
        'CORSRules': [
            {'AllowedMethods': allowed_methods,
             'AllowedOrigins': allowed_origins,
            },
        ]
    }

    e = assert_raises(ClientError, client.get_bucket_cors, Bucket=bucket_name)
    status = _get_status(e.response)
    eq(status, 404)

    client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)
    response = client.get_bucket_cors(Bucket=bucket_name)
    eq(response['CORSRules'][0]['AllowedMethods'], allowed_methods)
    eq(response['CORSRules'][0]['AllowedOrigins'], allowed_origins)

    client.delete_bucket_cors(Bucket=bucket_name)
    e = assert_raises(ClientError, client.get_bucket_cors, Bucket=bucket_name)
    status = _get_status(e.response)
    eq(status, 404)

def _cors_request_and_check(func, url, headers, expect_status, expect_allow_origin, expect_allow_methods):
    r = func(url, headers=headers)
    eq(r.status_code, expect_status)

    assert r.headers.get('access-control-allow-origin', None) == expect_allow_origin
    assert r.headers.get('access-control-allow-methods', None) == expect_allow_methods

@attr(resource='bucket')
@attr(method='get')
@attr(operation='check cors response when origin header set')
@attr(assertion='returning cors header')
@attr('cors')
def test_cors_origin_response():
    bucket_name = _setup_bucket_acl(bucket_acl='public-read')
    client = get_client()

    cors_config ={
        'CORSRules': [
            {'AllowedMethods': ['GET'],
             'AllowedOrigins': ['*suffix'],
            },
            {'AllowedMethods': ['GET'],
             'AllowedOrigins': ['start*end'],
            },
            {'AllowedMethods': ['GET'],
             'AllowedOrigins': ['prefix*'],
            },
            {'AllowedMethods': ['PUT'],
             'AllowedOrigins': ['*.put'],
            }
        ]
    }

    e = assert_raises(ClientError, client.get_bucket_cors, Bucket=bucket_name)
    status = _get_status(e.response)
    eq(status, 404)

    client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)

    time.sleep(3)

    url = _get_post_url(bucket_name)

    _cors_request_and_check(requests.get, url, None, 200, None, None)
    _cors_request_and_check(requests.get, url, {'Origin': 'foo.suffix'}, 200, 'foo.suffix', 'GET')
    _cors_request_and_check(requests.get, url, {'Origin': 'foo.bar'}, 200, None, None)
    _cors_request_and_check(requests.get, url, {'Origin': 'foo.suffix.get'}, 200, None, None)
    _cors_request_and_check(requests.get, url, {'Origin': 'startend'}, 200, 'startend', 'GET')
    _cors_request_and_check(requests.get, url, {'Origin': 'start1end'}, 200, 'start1end', 'GET')
    _cors_request_and_check(requests.get, url, {'Origin': 'start12end'}, 200, 'start12end', 'GET')
    _cors_request_and_check(requests.get, url, {'Origin': '0start12end'}, 200, None, None)
    _cors_request_and_check(requests.get, url, {'Origin': 'prefix'}, 200, 'prefix', 'GET')
    _cors_request_and_check(requests.get, url, {'Origin': 'prefix.suffix'}, 200, 'prefix.suffix', 'GET')
    _cors_request_and_check(requests.get, url, {'Origin': 'bla.prefix'}, 200, None, None)

    obj_url = '{u}/{o}'.format(u=url, o='bar')
    _cors_request_and_check(requests.get, obj_url, {'Origin': 'foo.suffix'}, 404, 'foo.suffix', 'GET')
    _cors_request_and_check(requests.put, obj_url, {'Origin': 'foo.suffix', 'Access-Control-Request-Method': 'GET',
                                                    'content-length': '0'}, 403, 'foo.suffix', 'GET')
    _cors_request_and_check(requests.put, obj_url, {'Origin': 'foo.suffix', 'Access-Control-Request-Method': 'PUT',
                                                    'content-length': '0'}, 403, None, None)

    _cors_request_and_check(requests.put, obj_url, {'Origin': 'foo.suffix', 'Access-Control-Request-Method': 'DELETE',
                                                    'content-length': '0'}, 403, None, None)
    _cors_request_and_check(requests.put, obj_url, {'Origin': 'foo.suffix', 'content-length': '0'}, 403, None, None)

    _cors_request_and_check(requests.put, obj_url, {'Origin': 'foo.put', 'content-length': '0'}, 403, 'foo.put', 'PUT')

    _cors_request_and_check(requests.get, obj_url, {'Origin': 'foo.suffix'}, 404, 'foo.suffix', 'GET')

    _cors_request_and_check(requests.options, url, None, 400, None, None)
    _cors_request_and_check(requests.options, url, {'Origin': 'foo.suffix'}, 400, None, None)
    _cors_request_and_check(requests.options, url, {'Origin': 'bla'}, 400, None, None)
    _cors_request_and_check(requests.options, obj_url, {'Origin': 'foo.suffix', 'Access-Control-Request-Method': 'GET',
                                                    'content-length': '0'}, 200, 'foo.suffix', 'GET')
    _cors_request_and_check(requests.options, url, {'Origin': 'foo.bar', 'Access-Control-Request-Method': 'GET'}, 403, None, None)
    _cors_request_and_check(requests.options, url, {'Origin': 'foo.suffix.get', 'Access-Control-Request-Method': 'GET'}, 403, None, None)
    _cors_request_and_check(requests.options, url, {'Origin': 'startend', 'Access-Control-Request-Method': 'GET'}, 200, 'startend', 'GET')
    _cors_request_and_check(requests.options, url, {'Origin': 'start1end', 'Access-Control-Request-Method': 'GET'}, 200, 'start1end', 'GET')
    _cors_request_and_check(requests.options, url, {'Origin': 'start12end', 'Access-Control-Request-Method': 'GET'}, 200, 'start12end', 'GET')
    _cors_request_and_check(requests.options, url, {'Origin': '0start12end', 'Access-Control-Request-Method': 'GET'}, 403, None, None)
    _cors_request_and_check(requests.options, url, {'Origin': 'prefix', 'Access-Control-Request-Method': 'GET'}, 200, 'prefix', 'GET')
    _cors_request_and_check(requests.options, url, {'Origin': 'prefix.suffix', 'Access-Control-Request-Method': 'GET'}, 200, 'prefix.suffix', 'GET')
    _cors_request_and_check(requests.options, url, {'Origin': 'bla.prefix', 'Access-Control-Request-Method': 'GET'}, 403, None, None)
    _cors_request_and_check(requests.options, url, {'Origin': 'foo.put', 'Access-Control-Request-Method': 'GET'}, 403, None, None)
    _cors_request_and_check(requests.options, url, {'Origin': 'foo.put', 'Access-Control-Request-Method': 'PUT'}, 200, 'foo.put', 'PUT')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='check cors response when origin is set to wildcard')
@attr(assertion='returning cors header')
@attr('cors')
def test_cors_origin_wildcard():
    bucket_name = _setup_bucket_acl(bucket_acl='public-read')
    client = get_client()

    cors_config ={
        'CORSRules': [
            {'AllowedMethods': ['GET'],
             'AllowedOrigins': ['*'],
            },
        ]
    }

    e = assert_raises(ClientError, client.get_bucket_cors, Bucket=bucket_name)
    status = _get_status(e.response)
    eq(status, 404)

    client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)

    time.sleep(3)

    url = _get_post_url(bucket_name)

    _cors_request_and_check(requests.get, url, None, 200, None, None)
    _cors_request_and_check(requests.get, url, {'Origin': 'example.origin'}, 200, '*', 'GET')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='check cors response when Access-Control-Request-Headers is set in option request')
@attr(assertion='returning cors header')
@attr('cors')
def test_cors_header_option():
    bucket_name = _setup_bucket_acl(bucket_acl='public-read')
    client = get_client()

    cors_config ={
        'CORSRules': [
            {'AllowedMethods': ['GET'],
             'AllowedOrigins': ['*'],
             'ExposeHeaders': ['x-amz-meta-header1'],
            },
        ]
    }

    e = assert_raises(ClientError, client.get_bucket_cors, Bucket=bucket_name)
    status = _get_status(e.response)
    eq(status, 404)

    client.put_bucket_cors(Bucket=bucket_name, CORSConfiguration=cors_config)

    time.sleep(3)

    url = _get_post_url(bucket_name)
    obj_url = '{u}/{o}'.format(u=url, o='bar')

    _cors_request_and_check(requests.options, obj_url, {'Origin': 'example.origin','Access-Control-Request-Headers':'x-amz-meta-header2','Access-Control-Request-Method':'GET'}, 403, None, None)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='put tags')
@attr(assertion='succeeds')
@attr('tagging')
def test_set_tagging():
    bucket_name = get_new_bucket()
    client = get_client()

    tags={
        'TagSet': [
            {
                'Key': 'Hello',
                'Value': 'World'
            },
        ]
    }

    e = assert_raises(ClientError, client.get_bucket_tagging, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchTagSetError')

    client.put_bucket_tagging(Bucket=bucket_name, Tagging=tags)

    response = client.get_bucket_tagging(Bucket=bucket_name)
    eq(len(response['TagSet']), 1)
    eq(response['TagSet'][0]['Key'], 'Hello')
    eq(response['TagSet'][0]['Value'], 'World')

    client.delete_bucket_tagging(Bucket=bucket_name)
    e = assert_raises(ClientError, client.get_bucket_tagging, Bucket=bucket_name)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchTagSetError')


class FakeFile(object):
    """
    file that simulates seek, tell, and current character
    """
    def __init__(self, char='A', interrupt=None):
        self.offset = 0
        self.char = bytes(char, 'utf-8')
        self.interrupt = interrupt

    def seek(self, offset, whence=os.SEEK_SET):
        if whence == os.SEEK_SET:
            self.offset = offset
        elif whence == os.SEEK_END:
            self.offset = self.size + offset;
        elif whence == os.SEEK_CUR:
            self.offset += offset

    def tell(self):
        return self.offset

class FakeWriteFile(FakeFile):
    """
    file that simulates interruptable reads of constant data
    """
    def __init__(self, size, char='A', interrupt=None):
        FakeFile.__init__(self, char, interrupt)
        self.size = size

    def read(self, size=-1):
        if size < 0:
            size = self.size - self.offset
        count = min(size, self.size - self.offset)
        self.offset += count

        # Sneaky! do stuff before we return (the last time)
        if self.interrupt != None and self.offset == self.size and count > 0:
            self.interrupt()

        return self.char*count

class FakeReadFile(FakeFile):
    """
    file that simulates writes, interrupting after the second
    """
    def __init__(self, size, char='A', interrupt=None):
        FakeFile.__init__(self, char, interrupt)
        self.interrupted = False
        self.size = 0
        self.expected_size = size

    def write(self, chars):
        eq(chars, self.char*len(chars))
        self.offset += len(chars)
        self.size += len(chars)

        # Sneaky! do stuff on the second seek
        if not self.interrupted and self.interrupt != None \
                and self.offset > 0:
            self.interrupt()
            self.interrupted = True

    def close(self):
        eq(self.size, self.expected_size)

class FakeFileVerifier(object):
    """
    file that verifies expected data has been written
    """
    def __init__(self, char=None):
        self.char = char
        self.size = 0

    def write(self, data):
        size = len(data)
        if self.char == None:
            self.char = data[0]
        self.size += size
        eq(data.decode(), self.char*size)

def _verify_atomic_key_data(bucket_name, key, size=-1, char=None):
    """
    Make sure file is of the expected size and (simulated) content
    """
    fp_verify = FakeFileVerifier(char)
    client = get_client()
    client.download_fileobj(bucket_name, key, fp_verify)
    if size >= 0:
        eq(fp_verify.size, size)

def _test_atomic_read(file_size):
    """
    Create a file of A's, use it to set_contents_from_file.
    Create a file of B's, use it to re-set_contents_from_file.
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    client = get_client()


    fp_a = FakeWriteFile(file_size, 'A')
    client.put_object(Bucket=bucket_name, Key='testobj', Body=fp_a)

    fp_b = FakeWriteFile(file_size, 'B')
    fp_a2 = FakeReadFile(file_size, 'A',
        lambda: client.put_object(Bucket=bucket_name, Key='testobj', Body=fp_b)
        )

    read_client = get_client()

    read_client.download_fileobj(bucket_name, 'testobj', fp_a2)
    fp_a2.close()

    _verify_atomic_key_data(bucket_name, 'testobj', file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='read atomicity')
@attr(assertion='1MB successful')
def test_atomic_read_1mb():
    _test_atomic_read(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='read atomicity')
@attr(assertion='4MB successful')
def test_atomic_read_4mb():
    _test_atomic_read(1024*1024*4)

@attr(resource='object')
@attr(method='put')
@attr(operation='read atomicity')
@attr(assertion='8MB successful')
def test_atomic_read_8mb():
    _test_atomic_read(1024*1024*8)

def _test_atomic_write(file_size):
    """
    Create a file of A's, use it to set_contents_from_file.
    Verify the contents are all A's.
    Create a file of B's, use it to re-set_contents_from_file.
    Before re-set continues, verify content's still A's
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    client = get_client()
    objname = 'testobj'


    # create <file_size> file of A's
    fp_a = FakeWriteFile(file_size, 'A')
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)


    # verify A's
    _verify_atomic_key_data(bucket_name, objname, file_size, 'A')

    # create <file_size> file of B's
    # but try to verify the file before we finish writing all the B's
    fp_b = FakeWriteFile(file_size, 'B',
        lambda: _verify_atomic_key_data(bucket_name, objname, file_size, 'A')
        )

    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    # verify B's
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='write atomicity')
@attr(assertion='1MB successful')
def test_atomic_write_1mb():
    _test_atomic_write(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='write atomicity')
@attr(assertion='4MB successful')
def test_atomic_write_4mb():
    _test_atomic_write(1024*1024*4)

@attr(resource='object')
@attr(method='put')
@attr(operation='write atomicity')
@attr(assertion='8MB successful')
def test_atomic_write_8mb():
    _test_atomic_write(1024*1024*8)

def _test_atomic_dual_write(file_size):
    """
    create an object, two sessions writing different contents
    confirm that it is all one or the other
    """
    bucket_name = get_new_bucket()
    objname = 'testobj'
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=objname)

    # write <file_size> file of B's
    # but before we're done, try to write all A's
    fp_a = FakeWriteFile(file_size, 'A')

    def rewind_put_fp_a():
        fp_a.seek(0)
        client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)

    fp_b = FakeWriteFile(file_size, 'B', rewind_put_fp_a)
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    # verify the file
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='1MB successful')
def test_atomic_dual_write_1mb():
    _test_atomic_dual_write(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='4MB successful')
def test_atomic_dual_write_4mb():
    _test_atomic_dual_write(1024*1024*4)

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='8MB successful')
def test_atomic_dual_write_8mb():
    _test_atomic_dual_write(1024*1024*8)

def _test_atomic_conditional_write(file_size):
    """
    Create a file of A's, use it to set_contents_from_file.
    Verify the contents are all A's.
    Create a file of B's, use it to re-set_contents_from_file.
    Before re-set continues, verify content's still A's
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    objname = 'testobj'
    client = get_client()

    # create <file_size> file of A's
    fp_a = FakeWriteFile(file_size, 'A')
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)

    fp_b = FakeWriteFile(file_size, 'B',
        lambda: _verify_atomic_key_data(bucket_name, objname, file_size, 'A')
        )

    # create <file_size> file of B's
    # but try to verify the file before we finish writing all the B's
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': '*'}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    # verify B's
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='write atomicity')
@attr(assertion='1MB successful')
@attr('fails_on_aws')
def test_atomic_conditional_write_1mb():
    _test_atomic_conditional_write(1024*1024)

def _test_atomic_dual_conditional_write(file_size):
    """
    create an object, two sessions writing different contents
    confirm that it is all one or the other
    """
    bucket_name = get_new_bucket()
    objname = 'testobj'
    client = get_client()

    fp_a = FakeWriteFile(file_size, 'A')
    response = client.put_object(Bucket=bucket_name, Key=objname, Body=fp_a)
    _verify_atomic_key_data(bucket_name, objname, file_size, 'A')
    etag_fp_a = response['ETag'].replace('"', '')

    # write <file_size> file of C's
    # but before we're done, try to write all B's
    fp_b = FakeWriteFile(file_size, 'B')
    lf = (lambda **kwargs: kwargs['params']['headers'].update({'If-Match': etag_fp_a}))
    client.meta.events.register('before-call.s3.PutObject', lf)
    def rewind_put_fp_b():
        fp_b.seek(0)
        client.put_object(Bucket=bucket_name, Key=objname, Body=fp_b)

    fp_c = FakeWriteFile(file_size, 'C', rewind_put_fp_b)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=objname, Body=fp_c)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

    # verify the file
    _verify_atomic_key_data(bucket_name, objname, file_size, 'B')

@attr(resource='object')
@attr(method='put')
@attr(operation='write one or the other')
@attr(assertion='1MB successful')
@attr('fails_on_aws')
# TODO: test not passing with SSL, fix this
@attr('fails_on_rgw')
def test_atomic_dual_conditional_write_1mb():
    _test_atomic_dual_conditional_write(1024*1024)

@attr(resource='object')
@attr(method='put')
@attr(operation='write file in deleted bucket')
@attr(assertion='fail 404')
@attr('fails_on_aws')
# TODO: test not passing with SSL, fix this
@attr('fails_on_rgw')
def test_atomic_write_bucket_gone():
    bucket_name = get_new_bucket()
    client = get_client()

    def remove_bucket():
        client.delete_bucket(Bucket=bucket_name)

    objname = 'foo'
    fp_a = FakeWriteFile(1024*1024, 'A', remove_bucket)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=objname, Body=fp_a)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='put')
@attr(operation='begin to overwrite file with multipart upload then abort')
@attr(assertion='read back original key contents')
def test_atomic_multipart_upload_write():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = client.create_multipart_upload(Bucket=bucket_name, Key='foo')
    upload_id = response['UploadId']

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

    client.abort_multipart_upload(Bucket=bucket_name, Key='foo', UploadId=upload_id)

    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

class Counter:
    def __init__(self, default_val):
        self.val = default_val

    def inc(self):
        self.val = self.val + 1

class ActionOnCount:
    def __init__(self, trigger_count, action):
        self.count = 0
        self.trigger_count = trigger_count
        self.action = action
        self.result = 0

    def trigger(self):
        self.count = self.count + 1

        if self.count == self.trigger_count:
            self.result = self.action()

@attr(resource='object')
@attr(method='put')
@attr(operation='multipart check for two writes of the same part, first write finishes last')
@attr(assertion='object contains correct content')
def test_multipart_resend_first_finishes_last():
    bucket_name = get_new_bucket()
    client = get_client()
    key_name = "mymultipart"

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key_name)
    upload_id = response['UploadId']

    #file_size = 8*1024*1024
    file_size = 8

    counter = Counter(0)
    # upload_part might read multiple times from the object
    # first time when it calculates md5, second time when it writes data
    # out. We want to interject only on the last time, but we can't be
    # sure how many times it's going to read, so let's have a test run
    # and count the number of reads

    fp_dry_run = FakeWriteFile(file_size, 'C',
        lambda: counter.inc()
        )

    parts = []

    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key_name, PartNumber=1, Body=fp_dry_run)

    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 1})
    client.complete_multipart_upload(Bucket=bucket_name, Key=key_name, UploadId=upload_id, MultipartUpload={'Parts': parts})

    client.delete_object(Bucket=bucket_name, Key=key_name)

    # clear parts
    parts[:] = []

    # ok, now for the actual test
    fp_b = FakeWriteFile(file_size, 'B')
    def upload_fp_b():
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key_name, Body=fp_b, PartNumber=1)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 1})

    action = ActionOnCount(counter.val, lambda: upload_fp_b())

    response = client.create_multipart_upload(Bucket=bucket_name, Key=key_name)
    upload_id = response['UploadId']

    fp_a = FakeWriteFile(file_size, 'A',
        lambda: action.trigger()
        )

    response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key_name, PartNumber=1, Body=fp_a)

    parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': 1})
    client.complete_multipart_upload(Bucket=bucket_name, Key=key_name, UploadId=upload_id, MultipartUpload={'Parts': parts})

    _verify_atomic_key_data(bucket_name, key_name, file_size, 'A')

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_request_response_code():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=4-7')

    fetched_content = _get_body(response)
    eq(fetched_content, content[4:8])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 4-7/11')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

def _generate_random_string(size):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_big_request_response_code():
    content = _generate_random_string(8*1024*1024)

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=3145728-5242880')

    fetched_content = _get_body(response)
    eq(fetched_content, content[3145728:5242881])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 3145728-5242880/8388608')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_request_skip_leading_bytes_response_code():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=4-')

    fetched_content = _get_body(response)
    eq(fetched_content, content[4:])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 4-10/11')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns correct data, 206')
def test_ranged_request_return_trailing_bytes_response_code():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)
    response = client.get_object(Bucket=bucket_name, Key='testobj', Range='bytes=-7')

    fetched_content = _get_body(response)
    eq(fetched_content, content[-7:])
    eq(response['ResponseMetadata']['HTTPHeaders']['content-range'], 'bytes 4-10/11')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 206)

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns invalid range, 416')
def test_ranged_request_invalid_range():
    content = 'testcontent'

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)

    # test invalid range
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='testobj', Range='bytes=40-50')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 416)
    eq(error_code, 'InvalidRange')

@attr(resource='object')
@attr(method='get')
@attr(operation='range')
@attr(assertion='returns invalid range, 416')
def test_ranged_request_empty_object():
    content = ''

    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='testobj', Body=content)

    # test invalid range
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='testobj', Range='bytes=40-50')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 416)
    eq(error_code, 'InvalidRange')

@attr(resource='bucket')
@attr(method='create')
@attr(operation='create versioned bucket')
@attr(assertion='can create and suspend bucket versioning')
@attr('versioning')
def test_versioning_bucket_create_suspend():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")

def check_obj_content(client, bucket_name, key, version_id, content):
    response = client.get_object(Bucket=bucket_name, Key=key, VersionId=version_id)
    if content is not None:
        body = _get_body(response)
        eq(body, content)
    else:
        eq(response['DeleteMarker'], True)

def check_obj_versions(client, bucket_name, key, version_ids, contents):
    # check to see if objects is pointing at correct version

    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    # obj versions in versions come out created last to first not first to last like version_ids & contents
    versions.reverse()
    i = 0

    for version in versions:
        eq(version['VersionId'], version_ids[i])
        eq(version['Key'], key)
        check_obj_content(client, bucket_name, key, version['VersionId'], contents[i])
        i += 1

def create_multiple_versions(client, bucket_name, key, num_versions, version_ids = None, contents = None, check_versions = True):
    contents = contents or []
    version_ids = version_ids or []

    for i in range(num_versions):
        body = 'content-{i}'.format(i=i)
        response = client.put_object(Bucket=bucket_name, Key=key, Body=body)
        version_id = response['VersionId']

        contents.append(body)
        version_ids.append(version_id)

    if check_versions:
        check_obj_versions(client, bucket_name, key, version_ids, contents)

    return (version_ids, contents)

def remove_obj_version(client, bucket_name, key, version_ids, contents, index):
    eq(len(version_ids), len(contents))
    index = index % len(version_ids)
    rm_version_id = version_ids.pop(index)
    rm_content = contents.pop(index)

    check_obj_content(client, bucket_name, key, rm_version_id, rm_content)

    client.delete_object(Bucket=bucket_name, Key=key, VersionId=rm_version_id)

    if len(version_ids) != 0:
        check_obj_versions(client, bucket_name, key, version_ids, contents)

def clean_up_bucket(client, bucket_name, key, version_ids):
    for version_id in version_ids:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version_id)

    client.delete_bucket(Bucket=bucket_name)

def _do_test_create_remove_versions(client, bucket_name, key, num_versions, remove_start_idx, idx_inc):
    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    idx = remove_start_idx

    for j in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)
        idx += idx_inc

    response = client.list_object_versions(Bucket=bucket_name)
    if 'Versions' in response:
        print(response['Versions'])


@attr(resource='object')
@attr(method='create')
@attr(operation='create and remove versioned object')
@attr(assertion='can create access and remove appropriate versions')
@attr('versioning')
def test_versioning_obj_create_read_remove():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'MFADelete': 'Disabled', 'Status': 'Enabled'})
    key = 'testobj'
    num_versions = 5

    _do_test_create_remove_versions(client, bucket_name, key, num_versions, -1, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, -1, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 0, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 1, 0)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 4, -1)
    _do_test_create_remove_versions(client, bucket_name, key, num_versions, 3, 3)

@attr(resource='object')
@attr(method='create')
@attr(operation='create and remove versioned object and head')
@attr(assertion='can create access and remove appropriate versions')
@attr('versioning')
def test_versioning_obj_create_read_remove_head():
    bucket_name = get_new_bucket()

    client = get_client()
    client.put_bucket_versioning(Bucket=bucket_name, VersioningConfiguration={'MFADelete': 'Disabled', 'Status': 'Enabled'})
    key = 'testobj'
    num_versions = 5

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    # removes old head object, checks new one
    removed_version_id = version_ids.pop()
    contents.pop()
    num_versions = num_versions-1

    response = client.delete_object(Bucket=bucket_name, Key=key, VersionId=removed_version_id)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, contents[-1])

    # add a delete marker
    response = client.delete_object(Bucket=bucket_name, Key=key)
    eq(response['DeleteMarker'], True)

    delete_marker_version_id = response['VersionId']
    version_ids.append(delete_marker_version_id)

    response = client.list_object_versions(Bucket=bucket_name)
    eq(len(response['Versions']), num_versions)
    eq(len(response['DeleteMarkers']), 1)
    eq(response['DeleteMarkers'][0]['VersionId'], delete_marker_version_id)

    clean_up_bucket(client, bucket_name, key, version_ids)

@attr(resource='object')
@attr(method='create')
@attr(operation='create object, then switch to versioning')
@attr(assertion='behaves correctly')
@attr('versioning')
def test_versioning_obj_plain_null_version_removal():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    client = get_client()
    key = 'testobjfoo'
    content = 'fooz'
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    client.delete_object(Bucket=bucket_name, Key=key, VersionId='null')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='create')
@attr(operation='create object, then switch to versioning')
@attr(assertion='behaves correctly')
@attr('versioning')
def test_versioning_obj_plain_null_version_overwrite():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    client = get_client()
    key = 'testobjfoo'
    content = 'fooz'
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    content2 = 'zzz'
    response = client.put_object(Bucket=bucket_name, Key=key, Body=content2)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, content2)

    version_id = response['VersionId']
    client.delete_object(Bucket=bucket_name, Key=key, VersionId=version_id)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, content)

    client.delete_object(Bucket=bucket_name, Key=key, VersionId='null')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='create')
@attr(operation='create object, then switch to versioning')
@attr(assertion='behaves correctly')
@attr('versioning')
def test_versioning_obj_plain_null_version_overwrite_suspended():
    bucket_name = get_new_bucket()
    check_versioning(bucket_name, None)

    client = get_client()
    key = 'testobjbar'
    content = 'foooz'
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")

    content2 = 'zzz'
    response = client.put_object(Bucket=bucket_name, Key=key, Body=content2)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, content2)

    response = client.list_object_versions(Bucket=bucket_name)
    # original object with 'null' version id still counts as a version
    eq(len(response['Versions']), 1)

    client.delete_object(Bucket=bucket_name, Key=key, VersionId='null')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

def delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents):
    client.delete_object(Bucket=bucket_name, Key=key)

    # clear out old null objects in lists since they will get overwritten
    eq(len(version_ids), len(contents))
    i = 0
    for version_id in version_ids:
        if version_id == 'null':
            version_ids.pop(i)
            contents.pop(i)
        i += 1

    return (version_ids, contents)

def overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, content):
    client.put_object(Bucket=bucket_name, Key=key, Body=content)

    # clear out old null objects in lists since they will get overwritten
    eq(len(version_ids), len(contents))
    i = 0
    for version_id in version_ids:
        if version_id == 'null':
            version_ids.pop(i)
            contents.pop(i)
        i += 1

    # add new content with 'null' version id to the end
    contents.append(content)
    version_ids.append('null')

    return (version_ids, contents)


@attr(resource='object')
@attr(method='create')
@attr(operation='suspend versioned bucket')
@attr(assertion='suspended versioning behaves correctly')
@attr('versioning')
def test_versioning_obj_suspend_versions():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 5

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")

    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)
    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)

    overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, 'null content 1')
    overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, 'null content 2')
    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)
    overwrite_suspended_versioning_obj(client, bucket_name, key, version_ids, contents, 'null content 3')
    delete_suspended_versioning_obj(client, bucket_name, key, version_ids, contents)

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, 3, version_ids, contents)
    num_versions += 3

    for idx in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

    eq(len(version_ids), 0)
    eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='remove')
@attr(operation='create and remove versions')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_create_versions_remove_all():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 10

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)
    for idx in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

    eq(len(version_ids), 0)
    eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='remove')
@attr(operation='create and remove versions')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_create_versions_remove_special_names():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    keys = ['_testobj', '_', ':', ' ']
    num_versions = 10

    for key in keys:
        (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)
        for idx in range(num_versions):
            remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

        eq(len(version_ids), 0)
        eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='multipart')
@attr(operation='create and test multipart object')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_create_overwrite_multipart():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 3
    contents = []
    version_ids = []

    for i in range(num_versions):
        ret =  _do_test_multipart_upload_contents(bucket_name, key, 3)
        contents.append(ret)

    response = client.list_object_versions(Bucket=bucket_name)
    for version in response['Versions']:
        version_ids.append(version['VersionId'])

    version_ids.reverse()
    check_obj_versions(client, bucket_name, key, version_ids, contents)

    for idx in range(num_versions):
        remove_obj_version(client, bucket_name, key, version_ids, contents, idx)

    eq(len(version_ids), 0)
    eq(len(version_ids), len(contents))

@attr(resource='object')
@attr(method='multipart')
@attr(operation='list versioned objects')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_obj_list_marker():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    key2 = 'testobj-1'
    num_versions = 5

    contents = []
    version_ids = []
    contents2 = []
    version_ids2 = []

    # for key #1
    for i in range(num_versions):
        body = 'content-{i}'.format(i=i)
        response = client.put_object(Bucket=bucket_name, Key=key, Body=body)
        version_id = response['VersionId']

        contents.append(body)
        version_ids.append(version_id)

    # for key #2
    for i in range(num_versions):
        body = 'content-{i}'.format(i=i)
        response = client.put_object(Bucket=bucket_name, Key=key2, Body=body)
        version_id = response['VersionId']

        contents2.append(body)
        version_ids2.append(version_id)

    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    # obj versions in versions come out created last to first not first to last like version_ids & contents
    versions.reverse()

    i = 0
    # test the last 5 created objects first
    for i in range(5):
        version = versions[i]
        eq(version['VersionId'], version_ids2[i])
        eq(version['Key'], key2)
        check_obj_content(client, bucket_name, key2, version['VersionId'], contents2[i])
        i += 1

    # then the first 5
    for j in range(5):
        version = versions[i]
        eq(version['VersionId'], version_ids[j])
        eq(version['Key'], key)
        check_obj_content(client, bucket_name, key, version['VersionId'], contents[j])
        i += 1

@attr(resource='object')
@attr(method='multipart')
@attr(operation='create and test versioned object copying')
@attr(assertion='everything works')
@attr('versioning')
def test_versioning_copy_obj_version():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'testobj'
    num_versions = 3

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    for i in range(num_versions):
        new_key_name = 'key_{i}'.format(i=i)
        copy_source = {'Bucket': bucket_name, 'Key': key, 'VersionId': version_ids[i]}
        client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key=new_key_name)
        response = client.get_object(Bucket=bucket_name, Key=new_key_name)
        body = _get_body(response)
        eq(body, contents[i])

    another_bucket_name = get_new_bucket()

    for i in range(num_versions):
        new_key_name = 'key_{i}'.format(i=i)
        copy_source = {'Bucket': bucket_name, 'Key': key, 'VersionId': version_ids[i]}
        client.copy_object(Bucket=another_bucket_name, CopySource=copy_source, Key=new_key_name)
        response = client.get_object(Bucket=another_bucket_name, Key=new_key_name)
        body = _get_body(response)
        eq(body, contents[i])

    new_key_name = 'new_key'
    copy_source = {'Bucket': bucket_name, 'Key': key}
    client.copy_object(Bucket=another_bucket_name, CopySource=copy_source, Key=new_key_name)

    response = client.get_object(Bucket=another_bucket_name, Key=new_key_name)
    body = _get_body(response)
    eq(body, contents[-1])

@attr(resource='object')
@attr(method='delete')
@attr(operation='delete multiple versions')
@attr(assertion='deletes multiple versions of an object with a single call')
@attr('versioning')
def test_versioning_multi_object_delete():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'key'
    num_versions = 2

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    versions.reverse()

    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

    # now remove again, should all succeed due to idempotency
    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='delete')
@attr(operation='delete multiple versions')
@attr(assertion='deletes multiple versions of an object and delete marker with a single call')
@attr('versioning')
def test_versioning_multi_object_delete_with_marker():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'key'
    num_versions = 2

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    client.delete_object(Bucket=bucket_name, Key=key)
    response = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    delete_markers = response['DeleteMarkers']

    version_ids.append(delete_markers[0]['VersionId'])
    eq(len(version_ids), 3)
    eq(len(delete_markers), 1)

    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    for delete_marker in delete_markers:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=delete_marker['VersionId'])

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)
    eq(('DeleteMarkers' in response), False)

    for version in versions:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=version['VersionId'])

    for delete_marker in delete_markers:
        client.delete_object(Bucket=bucket_name, Key=key, VersionId=delete_marker['VersionId'])

    # now remove again, should all succeed due to idempotency
    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)
    eq(('DeleteMarkers' in response), False)

@attr(resource='object')
@attr(method='delete')
@attr(operation='multi delete create marker')
@attr(assertion='returns correct marker version id')
@attr('versioning')
def test_versioning_multi_object_delete_with_marker_create():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'key'

    response = client.delete_object(Bucket=bucket_name, Key=key)
    delete_marker_version_id = response['VersionId']

    response = client.list_object_versions(Bucket=bucket_name)
    delete_markers = response['DeleteMarkers']

    eq(len(delete_markers), 1)
    eq(delete_marker_version_id, delete_markers[0]['VersionId'])
    eq(key, delete_markers[0]['Key'])

@attr(resource='object')
@attr(method='put')
@attr(operation='change acl on an object version changes specific version')
@attr(assertion='works')
@attr('versioning')
def test_versioned_object_acl():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'xyz'
    num_versions = 3

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    version_id = version_ids[1]

    response = client.get_object_acl(Bucket=bucket_name, Key=key, VersionId=version_id)

    display_name = get_main_display_name()
    user_id = get_main_user_id()

    eq(response['Owner']['DisplayName'], display_name)
    eq(response['Owner']['ID'], user_id)

    grants = response['Grants']
    default_policy = [
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ]

    check_grants(grants, default_policy)

    client.put_object_acl(ACL='public-read',Bucket=bucket_name, Key=key, VersionId=version_id)

    response = client.get_object_acl(Bucket=bucket_name, Key=key, VersionId=version_id)
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

    client.put_object(Bucket=bucket_name, Key=key)

    response = client.get_object_acl(Bucket=bucket_name, Key=key)
    grants = response['Grants']
    check_grants(grants, default_policy)

@attr(resource='object')
@attr(method='put')
@attr(operation='change acl on an object with no version specified changes latest version')
@attr(assertion='works')
@attr('versioning')
def test_versioned_object_acl_no_version_specified():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'xyz'
    num_versions = 3

    (version_ids, contents) = create_multiple_versions(client, bucket_name, key, num_versions)

    response = client.get_object(Bucket=bucket_name, Key=key)
    version_id = response['VersionId']

    response = client.get_object_acl(Bucket=bucket_name, Key=key, VersionId=version_id)

    display_name = get_main_display_name()
    user_id = get_main_user_id()

    eq(response['Owner']['DisplayName'], display_name)
    eq(response['Owner']['ID'], user_id)

    grants = response['Grants']
    default_policy = [
            dict(
                Permission='FULL_CONTROL',
                ID=user_id,
                DisplayName=display_name,
                URI=None,
                EmailAddress=None,
                Type='CanonicalUser',
                ),
            ]

    check_grants(grants, default_policy)

    client.put_object_acl(ACL='public-read',Bucket=bucket_name, Key=key)

    response = client.get_object_acl(Bucket=bucket_name, Key=key, VersionId=version_id)
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

def _do_create_object(client, bucket_name, key, i):
    body = 'data {i}'.format(i=i)
    client.put_object(Bucket=bucket_name, Key=key, Body=body)

def _do_remove_ver(client, bucket_name, key, version_id):
    client.delete_object(Bucket=bucket_name, Key=key, VersionId=version_id)

def _do_create_versioned_obj_concurrent(client, bucket_name, key, num):
    t = []
    for i in range(num):
        thr = threading.Thread(target = _do_create_object, args=(client, bucket_name, key, i))
        thr.start()
        t.append(thr)
    return t

def _do_clear_versioned_bucket_concurrent(client, bucket_name):
    t = []
    response = client.list_object_versions(Bucket=bucket_name)
    for version in response.get('Versions', []):
        thr = threading.Thread(target = _do_remove_ver, args=(client, bucket_name, version['Key'], version['VersionId']))
        thr.start()
        t.append(thr)
    return t

def _do_wait_completion(t):
    for thr in t:
        thr.join()

@attr(resource='object')
@attr(method='put')
@attr(operation='concurrent creation of objects, concurrent removal')
@attr(assertion='works')
# TODO: remove fails_on_rgw when https://tracker.ceph.com/issues/39142 is resolved
@attr('fails_on_rgw')
@attr('versioning')
def test_versioned_concurrent_object_create_concurrent_remove():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'myobj'
    num_versions = 5

    for i in range(5):
        t = _do_create_versioned_obj_concurrent(client, bucket_name, key, num_versions)
        _do_wait_completion(t)

        response = client.list_object_versions(Bucket=bucket_name)
        versions = response['Versions']

        eq(len(versions), num_versions)

        t = _do_clear_versioned_bucket_concurrent(client, bucket_name)
        _do_wait_completion(t)

        response = client.list_object_versions(Bucket=bucket_name)
        eq(('Versions' in response), False)

@attr(resource='object')
@attr(method='put')
@attr(operation='concurrent creation and removal of objects')
@attr(assertion='works')
@attr('versioning')
def test_versioned_concurrent_object_create_and_remove():
    bucket_name = get_new_bucket()
    client = get_client()

    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    key = 'myobj'
    num_versions = 3

    all_threads = []

    for i in range(3):

        t = _do_create_versioned_obj_concurrent(client, bucket_name, key, num_versions)
        all_threads.append(t)

        t = _do_clear_versioned_bucket_concurrent(client, bucket_name)
        all_threads.append(t)

    for t in all_threads:
        _do_wait_completion(t)

    t = _do_clear_versioned_bucket_concurrent(client, bucket_name)
    _do_wait_completion(t)

    response = client.list_object_versions(Bucket=bucket_name)
    eq(('Versions' in response), False)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config')
@attr('lifecycle')
def test_lifecycle_set():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Days': 1}, 'Prefix': 'test1/', 'Status':'Enabled'},
           {'ID': 'rule2', 'Expiration': {'Days': 2}, 'Prefix': 'test2/', 'Status':'Disabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='get lifecycle config')
@attr('lifecycle')
def test_lifecycle_get():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'test1/', 'Expiration': {'Days': 31}, 'Prefix': 'test1/', 'Status':'Enabled'},
           {'ID': 'test2/', 'Expiration': {'Days': 120}, 'Prefix': 'test2/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    eq(response['Rules'], rules)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='get lifecycle config no id')
@attr('lifecycle')
def test_lifecycle_get_no_id():
    bucket_name = get_new_bucket()
    client = get_client()

    rules=[{'Expiration': {'Days': 31}, 'Prefix': 'test1/', 'Status':'Enabled'},
           {'Expiration': {'Days': 120}, 'Prefix': 'test2/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    current_lc = response['Rules']

    Rule = namedtuple('Rule',['prefix','status','days'])
    rules = {'rule1' : Rule('test1/','Enabled',31),
             'rule2' : Rule('test2/','Enabled',120)}

    for lc_rule in current_lc:
        if lc_rule['Prefix'] == rules['rule1'].prefix:
            eq(lc_rule['Expiration']['Days'], rules['rule1'].days)
            eq(lc_rule['Status'], rules['rule1'].status)
            assert 'ID' in lc_rule
        elif lc_rule['Prefix'] == rules['rule2'].prefix:
            eq(lc_rule['Expiration']['Days'], rules['rule2'].days)
            eq(lc_rule['Status'], rules['rule2'].status)
            assert 'ID' in lc_rule
        else:
            # neither of the rules we supplied was returned, something wrong
            print("rules not right")
            assert False

# The test harness for lifecycle is configured to treat days as 10 second intervals.
@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle expiration')
@attr('lifecycle')
@attr('lifecycle_expiration')
@attr('fails_on_aws')
def test_lifecycle_expiration():
    bucket_name = _create_objects(keys=['expire1/foo', 'expire1/bar', 'keep2/foo',
                                        'keep2/bar', 'expire3/foo', 'expire3/bar'])
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Days': 1}, 'Prefix': 'expire1/', 'Status':'Enabled'},
           {'ID': 'rule2', 'Expiration': {'Days': 4}, 'Prefix': 'expire3/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    response = client.list_objects(Bucket=bucket_name)
    init_objects = response['Contents']

    time.sleep(28)
    response = client.list_objects(Bucket=bucket_name)
    expire1_objects = response['Contents']

    time.sleep(10)
    response = client.list_objects(Bucket=bucket_name)
    keep2_objects = response['Contents']

    time.sleep(20)
    response = client.list_objects(Bucket=bucket_name)
    expire3_objects = response['Contents']

    eq(len(init_objects), 6)
    eq(len(expire1_objects), 4)
    eq(len(keep2_objects), 4)
    eq(len(expire3_objects), 2)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle expiration with list-objects-v2')
@attr('lifecycle')
@attr('lifecycle_expiration')
@attr('fails_on_aws')
@attr('list-objects-v2')
def test_lifecyclev2_expiration():
    bucket_name = _create_objects(keys=['expire1/foo', 'expire1/bar', 'keep2/foo',
                                        'keep2/bar', 'expire3/foo', 'expire3/bar'])
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Days': 1}, 'Prefix': 'expire1/', 'Status':'Enabled'},
           {'ID': 'rule2', 'Expiration': {'Days': 4}, 'Prefix': 'expire3/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    response = client.list_objects_v2(Bucket=bucket_name)
    init_objects = response['Contents']

    time.sleep(28)
    response = client.list_objects_v2(Bucket=bucket_name)
    expire1_objects = response['Contents']

    time.sleep(10)
    response = client.list_objects_v2(Bucket=bucket_name)
    keep2_objects = response['Contents']

    time.sleep(20)
    response = client.list_objects_v2(Bucket=bucket_name)
    expire3_objects = response['Contents']

    eq(len(init_objects), 6)
    eq(len(expire1_objects), 4)
    eq(len(keep2_objects), 4)
    eq(len(expire3_objects), 2)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle expiration on versining enabled bucket')
@attr('lifecycle')
@attr('lifecycle_expiration')
@attr('fails_on_aws')
def test_lifecycle_expiration_versioning_enabled():
    bucket_name = get_new_bucket()
    client = get_client()
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    create_multiple_versions(client, bucket_name, "test1/a", 1)
    client.delete_object(Bucket=bucket_name, Key="test1/a")

    rules=[{'ID': 'rule1', 'Expiration': {'Days': 1}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    time.sleep(30)

    response  = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    delete_markers = response['DeleteMarkers']
    eq(len(versions), 1)
    eq(len(delete_markers), 1)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='id too long in lifecycle rule')
@attr('lifecycle')
@attr(assertion='fails 400')
def test_lifecycle_id_too_long():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 256*'a', 'Expiration': {'Days': 2}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='same id')
@attr('lifecycle')
@attr(assertion='fails 400')
def test_lifecycle_same_id():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Days': 1}, 'Prefix': 'test1/', 'Status':'Enabled'},
           {'ID': 'rule1', 'Expiration': {'Days': 2}, 'Prefix': 'test2/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidArgument')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='invalid status in lifecycle rule')
@attr('lifecycle')
@attr(assertion='fails 400')
def test_lifecycle_invalid_status():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Days': 2}, 'Prefix': 'test1/', 'Status':'enabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'MalformedXML')

    rules=[{'ID': 'rule1', 'Expiration': {'Days': 2}, 'Prefix': 'test1/', 'Status':'disabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'MalformedXML')

    rules=[{'ID': 'rule1', 'Expiration': {'Days': 2}, 'Prefix': 'test1/', 'Status':'invalid'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'MalformedXML')

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with expiration date')
@attr('lifecycle')
def test_lifecycle_set_date():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Date': '2017-09-27'}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with not iso8601 date')
@attr('lifecycle')
@attr(assertion='fails 400')
def test_lifecycle_set_invalid_date():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Date': '20200101'}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}

    e = assert_raises(ClientError, client.put_bucket_lifecycle_configuration, Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle expiration with date')
@attr('lifecycle')
@attr('lifecycle_expiration')
@attr('fails_on_aws')
def test_lifecycle_expiration_date():
    bucket_name = _create_objects(keys=['past/foo', 'future/bar'])
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'Date': '2015-01-01'}, 'Prefix': 'past/', 'Status':'Enabled'},
           {'ID': 'rule2', 'Expiration': {'Date': '2030-01-01'}, 'Prefix': 'future/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    response = client.list_objects(Bucket=bucket_name)
    init_objects = response['Contents']

    time.sleep(20)
    response = client.list_objects(Bucket=bucket_name)
    expire_objects = response['Contents']

    eq(len(init_objects), 2)
    eq(len(expire_objects), 1)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle expiration days 0')
@attr('lifecycle')
@attr('lifecycle_expiration')
def test_lifecycle_expiration_days0():
    bucket_name = _create_objects(keys=['days0/foo', 'days0/bar'])
    client = get_client()

    rules=[{'Expiration': {'Days': 1}, 'ID': 'rule1', 'Prefix': 'days0/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    print(lifecycle)
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    time.sleep(20)

    response = client.list_objects(Bucket=bucket_name)
    expire_objects = response['Contents']

    eq(len(expire_objects), 0)


def setup_lifecycle_expiration(client, bucket_name, rule_id, delta_days,
                                    rule_prefix):
    rules=[{'ID': rule_id,
            'Expiration': {'Days': delta_days}, 'Prefix': rule_prefix,
            'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(
        Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    key = rule_prefix + '/foo'
    body = 'bar'
    response = client.put_object(Bucket=bucket_name, Key=key, Body=body)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    response = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
    return response

def check_lifecycle_expiration_header(response, start_time, rule_id,
                                      delta_days):
    print(response)
    #TODO: see how this can work
    #print(response['ResponseMetadata']['HTTPHeaders'])
    #exp_header = response['ResponseMetadata']['HTTPHeaders']['x-amz-expiration']
    #m = re.search(r'expiry-date="(.+)", rule-id="(.+)"', exp_header)

    #expiration = datetime.datetime.strptime(m.group(1),
    #                                        '%a %b %d %H:%M:%S %Y')
    #eq((expiration - start_time).days, delta_days)
    #eq(m.group(2), rule_id)

    return True

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle expiration header put')
@attr('lifecycle')
@attr('lifecycle_expiration')
def test_lifecycle_expiration_header_put():
    bucket_name = get_new_bucket()
    client = get_client()

    now = datetime.datetime.now(None)
    response = setup_lifecycle_expiration(
        client, bucket_name, 'rule1', 1, 'days1/')
    eq(check_lifecycle_expiration_header(response, now, 'rule1', 1), True)

@attr(resource='bucket')
@attr(method='head')
@attr(operation='test lifecycle expiration header head')
@attr('lifecycle')
@attr('lifecycle_expiration')
def test_lifecycle_expiration_header_head():
    bucket_name = get_new_bucket()
    client = get_client()

    now = datetime.datetime.now(None)
    response = setup_lifecycle_expiration(
        client, bucket_name, 'rule1', 1, 'days1')

    key = 'days1/' + '/foo'

    # stat the object, check header
    response = client.head_object(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    eq(check_lifecycle_expiration_header(response, now, 'rule1', 1), True)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with noncurrent version expiration')
@attr('lifecycle')
def test_lifecycle_set_noncurrent():
    bucket_name = _create_objects(keys=['past/foo', 'future/bar'])
    client = get_client()
    rules=[{'ID': 'rule1', 'NoncurrentVersionExpiration': {'NoncurrentDays': 2}, 'Prefix': 'past/', 'Status':'Enabled'},
           {'ID': 'rule2', 'NoncurrentVersionExpiration': {'NoncurrentDays': 3}, 'Prefix': 'future/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle non-current version expiration')
@attr('lifecycle')
@attr('lifecycle_expiration')
@attr('fails_on_aws')
def test_lifecycle_noncur_expiration():
    bucket_name = get_new_bucket()
    client = get_client()
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    create_multiple_versions(client, bucket_name, "test1/a", 3)
    # not checking the object contents on the second run, because the function doesn't support multiple checks
    create_multiple_versions(client, bucket_name, "test2/abc", 3, check_versions=False)

    response  = client.list_object_versions(Bucket=bucket_name)
    init_versions = response['Versions']

    rules=[{'ID': 'rule1', 'NoncurrentVersionExpiration': {'NoncurrentDays': 2}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    time.sleep(50)

    response  = client.list_object_versions(Bucket=bucket_name)
    expire_versions = response['Versions']
    eq(len(init_versions), 6)
    eq(len(expire_versions), 4)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with delete marker expiration')
@attr('lifecycle')
def test_lifecycle_set_deletemarker():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'ExpiredObjectDeleteMarker': True}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with Filter')
@attr('lifecycle')
def test_lifecycle_set_filter():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'ExpiredObjectDeleteMarker': True}, 'Filter': {'Prefix': 'foo'}, 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with empty Filter')
@attr('lifecycle')
def test_lifecycle_set_empty_filter():
    bucket_name = get_new_bucket()
    client = get_client()
    rules=[{'ID': 'rule1', 'Expiration': {'ExpiredObjectDeleteMarker': True}, 'Filter': {}, 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle delete marker expiration')
@attr('lifecycle')
@attr('lifecycle_expiration')
@attr('fails_on_aws')
def test_lifecycle_deletemarker_expiration():
    bucket_name = get_new_bucket()
    client = get_client()
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    create_multiple_versions(client, bucket_name, "test1/a", 1)
    create_multiple_versions(client, bucket_name, "test2/abc", 1, check_versions=False)
    client.delete_object(Bucket=bucket_name, Key="test1/a")
    client.delete_object(Bucket=bucket_name, Key="test2/abc")

    response  = client.list_object_versions(Bucket=bucket_name)
    init_versions = response['Versions']
    deleted_versions = response['DeleteMarkers']
    total_init_versions = init_versions + deleted_versions

    rules=[{'ID': 'rule1', 'NoncurrentVersionExpiration': {'NoncurrentDays': 1}, 'Expiration': {'ExpiredObjectDeleteMarker': True}, 'Prefix': 'test1/', 'Status':'Enabled'}]
    lifecycle = {'Rules': rules}
    client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    time.sleep(50)

    response  = client.list_object_versions(Bucket=bucket_name)
    init_versions = response['Versions']
    deleted_versions = response['DeleteMarkers']
    total_expire_versions = init_versions + deleted_versions

    eq(len(total_init_versions), 4)
    eq(len(total_expire_versions), 2)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='set lifecycle config with multipart expiration')
@attr('lifecycle')
def test_lifecycle_set_multipart():
    bucket_name = get_new_bucket()
    client = get_client()
    rules = [
        {'ID': 'rule1', 'Prefix': 'test1/', 'Status': 'Enabled',
         'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 2}},
        {'ID': 'rule2', 'Prefix': 'test2/', 'Status': 'Disabled',
         'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 3}}
    ]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='bucket')
@attr(method='put')
@attr(operation='test lifecycle multipart expiration')
@attr('lifecycle')
@attr('lifecycle_expiration')
@attr('fails_on_aws')
def test_lifecycle_multipart_expiration():
    bucket_name = get_new_bucket()
    client = get_client()

    key_names = ['test1/a', 'test2/']
    upload_ids = []

    for key in key_names:
        response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
        upload_ids.append(response['UploadId'])

    response = client.list_multipart_uploads(Bucket=bucket_name)
    init_uploads = response['Uploads']

    rules = [
        {'ID': 'rule1', 'Prefix': 'test1/', 'Status': 'Enabled',
         'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 2}},
    ]
    lifecycle = {'Rules': rules}
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    time.sleep(50)

    response = client.list_multipart_uploads(Bucket=bucket_name)
    expired_uploads = response['Uploads']
    eq(len(init_uploads), 2)
    eq(len(expired_uploads), 1)


def _test_encryption_sse_customer_write(file_size):
    """
    Tests Create a file of A's, use it to set_contents_from_file.
    Create a file of B's, use it to re-set_contents_from_file.
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'testobj'
    data = 'A'*file_size
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw=='
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=key, Body=data)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.GetObject', lf)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, data)


@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-C encrypted transfer 1 byte')
@attr(assertion='success')
@attr('encryption')
def test_encrypted_transfer_1b():
    _test_encryption_sse_customer_write(1)


@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-C encrypted transfer 1KB')
@attr(assertion='success')
@attr('encryption')
def test_encrypted_transfer_1kb():
    _test_encryption_sse_customer_write(1024)


@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-C encrypted transfer 1MB')
@attr(assertion='success')
@attr('encryption')
def test_encrypted_transfer_1MB():
    _test_encryption_sse_customer_write(1024*1024)


@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-C encrypted transfer 13 bytes')
@attr(assertion='success')
@attr('encryption')
def test_encrypted_transfer_13b():
    _test_encryption_sse_customer_write(13)


@attr(assertion='success')
@attr('encryption')
def test_encryption_sse_c_method_head():
    bucket_name = get_new_bucket()
    client = get_client()
    data = 'A'*1000
    key = 'testobj'
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw=='
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=key, Body=data)

    e = assert_raises(ClientError, client.head_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.HeadObject', lf)
    response = client.head_object(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='put')
@attr(operation='write encrypted with SSE-C and read without SSE-C')
@attr(assertion='operation fails')
@attr('encryption')
def test_encryption_sse_c_present():
    bucket_name = get_new_bucket()
    client = get_client()
    data = 'A'*1000
    key = 'testobj'
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw=='
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=key, Body=data)

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='object')
@attr(method='put')
@attr(operation='write encrypted with SSE-C but read with other key')
@attr(assertion='operation fails')
@attr('encryption')
def test_encryption_sse_c_other_key():
    bucket_name = get_new_bucket()
    client = get_client()
    data = 'A'*100
    key = 'testobj'
    sse_client_headers_A = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw=='
    }
    sse_client_headers_B = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': '6b+WOZ1T3cqZMxgThRcXAQBrS5mXKdDUphvpxptl9/4=',
        'x-amz-server-side-encryption-customer-key-md5': 'arxBvwY2V4SiOne6yppVPQ=='
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers_A))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=key, Body=data)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers_B))
    client.meta.events.register('before-call.s3.GetObject', lf)
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='object')
@attr(method='put')
@attr(operation='write encrypted with SSE-C, but md5 is bad')
@attr(assertion='operation fails')
@attr('encryption')
def test_encryption_sse_c_invalid_md5():
    bucket_name = get_new_bucket()
    client = get_client()
    data = 'A'*100
    key = 'testobj'
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'AAAAAAAAAAAAAAAAAAAAAA=='
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key, Body=data)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='object')
@attr(method='put')
@attr(operation='write encrypted with SSE-C, but dont provide MD5')
@attr(assertion='operation fails')
@attr('encryption')
def test_encryption_sse_c_no_md5():
    bucket_name = get_new_bucket()
    client = get_client()
    data = 'A'*100
    key = 'testobj'
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key, Body=data)

@attr(resource='object')
@attr(method='put')
@attr(operation='declare SSE-C but do not provide key')
@attr(assertion='operation fails')
@attr('encryption')
def test_encryption_sse_c_no_key():
    bucket_name = get_new_bucket()
    client = get_client()
    data = 'A'*100
    key = 'testobj'
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key, Body=data)

@attr(resource='object')
@attr(method='put')
@attr(operation='Do not declare SSE-C but provide key and MD5')
@attr(assertion='operation successfull, no encryption')
@attr('encryption')
def test_encryption_key_no_sse_c():
    bucket_name = get_new_bucket()
    client = get_client()
    data = 'A'*100
    key = 'testobj'
    sse_client_headers = {
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw=='
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key, Body=data)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

def _multipart_upload_enc(client, bucket_name, key, size, part_size, init_headers, part_headers, metadata, resend_parts):
    """
    generate a multi-part upload for a random file of specifed size,
    if requested, generate a list of the parts
    return the upload descriptor
    """
    if client == None:
        client = get_client()

    lf = (lambda **kwargs: kwargs['params']['headers'].update(init_headers))
    client.meta.events.register('before-call.s3.CreateMultipartUpload', lf)
    if metadata == None:
        response = client.create_multipart_upload(Bucket=bucket_name, Key=key)
    else:
        response = client.create_multipart_upload(Bucket=bucket_name, Key=key, Metadata=metadata)

    upload_id = response['UploadId']
    s = ''
    parts = []
    for i, part in enumerate(generate_random(size, part_size)):
        # part_num is necessary because PartNumber for upload_part and in parts must start at 1 and i starts at 0
        part_num = i+1
        s += part
        lf = (lambda **kwargs: kwargs['params']['headers'].update(part_headers))
        client.meta.events.register('before-call.s3.UploadPart', lf)
        response = client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num, Body=part)
        parts.append({'ETag': response['ETag'].strip('"'), 'PartNumber': part_num})
        if i in resend_parts:
            lf = (lambda **kwargs: kwargs['params']['headers'].update(part_headers))
            client.meta.events.register('before-call.s3.UploadPart', lf)
            client.upload_part(UploadId=upload_id, Bucket=bucket_name, Key=key, PartNumber=part_num, Body=part)

    return (upload_id, s, parts)

def _check_content_using_range_enc(client, bucket_name, key, data, step, enc_headers=None):
    response = client.get_object(Bucket=bucket_name, Key=key)
    size = response['ContentLength']
    for ofs in range(0, size, step):
        toread = size - ofs
        if toread > step:
            toread = step
        end = ofs + toread - 1
        lf = (lambda **kwargs: kwargs['params']['headers'].update(enc_headers))
        client.meta.events.register('before-call.s3.GetObject', lf)
        r = 'bytes={s}-{e}'.format(s=ofs, e=end)
        response = client.get_object(Bucket=bucket_name, Key=key, Range=r)
        read_range = response['ContentLength']
        body = _get_body(response)
        eq(read_range, toread)
        eq(body, data[ofs:end+1])

@attr(resource='object')
@attr(method='put')
@attr(operation='complete multi-part upload')
@attr(assertion='successful')
@attr('encryption')
@attr('fails_on_aws') # allow-unordered is a non-standard extension
def test_encryption_sse_c_multipart_upload():
    bucket_name = get_new_bucket()
    client = get_client()
    key = "multipart_enc"
    content_type = 'text/plain'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    enc_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw==',
        'Content-Type': content_type
    }
    resend_parts = []

    (upload_id, data, parts) = _multipart_upload_enc(client, bucket_name, key, objlen,
            part_size=5*1024*1024, init_headers=enc_headers, part_headers=enc_headers, metadata=metadata, resend_parts=resend_parts)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(enc_headers))
    client.meta.events.register('before-call.s3.CompleteMultipartUpload', lf)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.head_bucket(Bucket=bucket_name)
    rgw_object_count = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-object-count', 1))
    eq(rgw_object_count, 1)
    rgw_bytes_used = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-bytes-used', objlen))
    eq(rgw_bytes_used, objlen)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(enc_headers))
    client.meta.events.register('before-call.s3.GetObject', lf)
    response = client.get_object(Bucket=bucket_name, Key=key)

    eq(response['Metadata'], metadata)
    eq(response['ResponseMetadata']['HTTPHeaders']['content-type'], content_type)

    body = _get_body(response)
    eq(body, data)
    size = response['ContentLength']
    eq(len(body), size)

    _check_content_using_range_enc(client, bucket_name, key, data, 1000000, enc_headers=enc_headers)
    _check_content_using_range_enc(client, bucket_name, key, data, 10000000, enc_headers=enc_headers)

@attr(resource='object')
@attr(method='put')
@attr(operation='multipart upload with bad key for uploading chunks')
@attr(assertion='successful')
@attr('encryption')
# TODO: remove this fails_on_rgw when I fix it
@attr('fails_on_rgw')
def test_encryption_sse_c_multipart_invalid_chunks_1():
    bucket_name = get_new_bucket()
    client = get_client()
    key = "multipart_enc"
    content_type = 'text/plain'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    init_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw==',
        'Content-Type': content_type
    }
    part_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': '6b+WOZ1T3cqZMxgThRcXAQBrS5mXKdDUphvpxptl9/4=',
        'x-amz-server-side-encryption-customer-key-md5': 'arxBvwY2V4SiOne6yppVPQ=='
    }
    resend_parts = []

    e = assert_raises(ClientError, _multipart_upload_enc, client=client,  bucket_name=bucket_name,
            key=key, size=objlen, part_size=5*1024*1024, init_headers=init_headers, part_headers=part_headers, metadata=metadata, resend_parts=resend_parts)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='object')
@attr(method='put')
@attr(operation='multipart upload with bad md5 for chunks')
@attr(assertion='successful')
@attr('encryption')
# TODO: remove this fails_on_rgw when I fix it
@attr('fails_on_rgw')
def test_encryption_sse_c_multipart_invalid_chunks_2():
    bucket_name = get_new_bucket()
    client = get_client()
    key = "multipart_enc"
    content_type = 'text/plain'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    init_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw==',
        'Content-Type': content_type
    }
    part_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'AAAAAAAAAAAAAAAAAAAAAA=='
    }
    resend_parts = []

    e = assert_raises(ClientError, _multipart_upload_enc, client=client,  bucket_name=bucket_name,
            key=key, size=objlen, part_size=5*1024*1024, init_headers=init_headers, part_headers=part_headers, metadata=metadata, resend_parts=resend_parts)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='object')
@attr(method='put')
@attr(operation='complete multi-part upload and download with bad key')
@attr(assertion='successful')
@attr('encryption')
def test_encryption_sse_c_multipart_bad_download():
    bucket_name = get_new_bucket()
    client = get_client()
    key = "multipart_enc"
    content_type = 'text/plain'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    put_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw==',
        'Content-Type': content_type
    }
    get_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': '6b+WOZ1T3cqZMxgThRcXAQBrS5mXKdDUphvpxptl9/4=',
        'x-amz-server-side-encryption-customer-key-md5': 'arxBvwY2V4SiOne6yppVPQ=='
    }
    resend_parts = []

    (upload_id, data, parts) = _multipart_upload_enc(client, bucket_name, key, objlen,
            part_size=5*1024*1024, init_headers=put_headers, part_headers=put_headers, metadata=metadata, resend_parts=resend_parts)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(put_headers))
    client.meta.events.register('before-call.s3.CompleteMultipartUpload', lf)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.head_bucket(Bucket=bucket_name)
    rgw_object_count = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-object-count', 1))
    eq(rgw_object_count, 1)
    rgw_bytes_used = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-bytes-used', objlen))
    eq(rgw_bytes_used, objlen)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(put_headers))
    client.meta.events.register('before-call.s3.GetObject', lf)
    response = client.get_object(Bucket=bucket_name, Key=key)

    eq(response['Metadata'], metadata)
    eq(response['ResponseMetadata']['HTTPHeaders']['content-type'], content_type)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(get_headers))
    client.meta.events.register('before-call.s3.GetObject', lf)
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)


@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
@attr('encryption')
def test_encryption_sse_c_post_object_authenticated_request():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["starts-with", "$x-amz-server-side-encryption-customer-algorithm", ""], \
    ["starts-with", "$x-amz-server-side-encryption-customer-key", ""], \
    ["starts-with", "$x-amz-server-side-encryption-customer-key-md5", ""], \
    ["content-length-range", 0, 1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),
    ('x-amz-server-side-encryption-customer-algorithm', 'AES256'), \
    ('x-amz-server-side-encryption-customer-key', 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs='), \
    ('x-amz-server-side-encryption-customer-key-md5', 'DWygnHRtgiJ77HCm+1rvHw=='), \
    ('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)

    get_headers = {
        'x-amz-server-side-encryption-customer-algorithm': 'AES256',
        'x-amz-server-side-encryption-customer-key': 'pO3upElrwuEXSoFwCfnZPdSsmt/xWeFa0N9KgDijwVs=',
        'x-amz-server-side-encryption-customer-key-md5': 'DWygnHRtgiJ77HCm+1rvHw=='
    }
    lf = (lambda **kwargs: kwargs['params']['headers'].update(get_headers))
    client.meta.events.register('before-call.s3.GetObject', lf)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(assertion='success')
@attr('encryption')
def _test_sse_kms_customer_write(file_size, key_id = 'testkey-1'):
    """
    Tests Create a file of A's, use it to set_contents_from_file.
    Create a file of B's, use it to re-set_contents_from_file.
    Re-read the contents, and confirm we get B's
    """
    bucket_name = get_new_bucket()
    client = get_client()
    sse_kms_client_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': key_id
    }
    data = 'A'*file_size

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_kms_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key='testobj', Body=data)

    response = client.get_object(Bucket=bucket_name, Key='testobj')
    body = _get_body(response)
    eq(body, data)






@attr(resource='object')
@attr(method='head')
@attr(operation='Test SSE-KMS encrypted does perform head properly')
@attr(assertion='success')
@attr('encryption')
def test_sse_kms_method_head():
    kms_keyid = get_main_kms_keyid()
    bucket_name = get_new_bucket()
    client = get_client()
    sse_kms_client_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': kms_keyid
    }
    data = 'A'*1000
    key = 'testobj'

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_kms_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=key, Body=data)

    response = client.head_object(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPHeaders']['x-amz-server-side-encryption'], 'aws:kms')
    eq(response['ResponseMetadata']['HTTPHeaders']['x-amz-server-side-encryption-aws-kms-key-id'], kms_keyid)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_kms_client_headers))
    client.meta.events.register('before-call.s3.HeadObject', lf)
    e = assert_raises(ClientError, client.head_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='object')
@attr(method='put')
@attr(operation='write encrypted with SSE-KMS and read without SSE-KMS')
@attr(assertion='operation success')
@attr('encryption')
def test_sse_kms_present():
    kms_keyid = get_main_kms_keyid()
    bucket_name = get_new_bucket()
    client = get_client()
    sse_kms_client_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': kms_keyid
    }
    data = 'A'*100
    key = 'testobj'

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_kms_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)
    client.put_object(Bucket=bucket_name, Key=key, Body=data)

    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, data)

@attr(resource='object')
@attr(method='put')
@attr(operation='declare SSE-KMS but do not provide key_id')
@attr(assertion='operation fails')
@attr('encryption')
def test_sse_kms_no_key():
    bucket_name = get_new_bucket()
    client = get_client()
    sse_kms_client_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
    }
    data = 'A'*100
    key = 'testobj'

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_kms_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key, Body=data)


@attr(resource='object')
@attr(method='put')
@attr(operation='Do not declare SSE-KMS but provide key_id')
@attr(assertion='operation successfull, no encryption')
@attr('encryption')
def test_sse_kms_not_declared():
    bucket_name = get_new_bucket()
    client = get_client()
    sse_kms_client_headers = {
        'x-amz-server-side-encryption-aws-kms-key-id': 'testkey-2'
    }
    data = 'A'*100
    key = 'testobj'

    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_kms_client_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key=key, Body=data)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

@attr(resource='object')
@attr(method='put')
@attr(operation='complete KMS multi-part upload')
@attr(assertion='successful')
@attr('encryption')
def test_sse_kms_multipart_upload():
    kms_keyid = get_main_kms_keyid()
    bucket_name = get_new_bucket()
    client = get_client()
    key = "multipart_enc"
    content_type = 'text/plain'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    enc_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': kms_keyid,
        'Content-Type': content_type
    }
    resend_parts = []

    (upload_id, data, parts) = _multipart_upload_enc(client, bucket_name, key, objlen,
            part_size=5*1024*1024, init_headers=enc_headers, part_headers=enc_headers, metadata=metadata, resend_parts=resend_parts)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(enc_headers))
    client.meta.events.register('before-call.s3.CompleteMultipartUpload', lf)
    client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})

    response = client.head_bucket(Bucket=bucket_name)
    rgw_object_count = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-object-count', 1))
    eq(rgw_object_count, 1)
    rgw_bytes_used = int(response['ResponseMetadata']['HTTPHeaders'].get('x-rgw-bytes-used', objlen))
    eq(rgw_bytes_used, objlen)

    lf = (lambda **kwargs: kwargs['params']['headers'].update(part_headers))
    client.meta.events.register('before-call.s3.UploadPart', lf)

    response = client.get_object(Bucket=bucket_name, Key=key)

    eq(response['Metadata'], metadata)
    eq(response['ResponseMetadata']['HTTPHeaders']['content-type'], content_type)

    body = _get_body(response)
    eq(body, data)
    size = response['ContentLength']
    eq(len(body), size)

    _check_content_using_range(key, bucket_name, data, 1000000)
    _check_content_using_range(key, bucket_name, data, 10000000)


@attr(resource='object')
@attr(method='put')
@attr(operation='multipart KMS upload with bad key_id for uploading chunks')
@attr(assertion='successful')
@attr('encryption')
def test_sse_kms_multipart_invalid_chunks_1():
    kms_keyid = get_main_kms_keyid()
    kms_keyid2 = get_secondary_kms_keyid()
    bucket_name = get_new_bucket()
    client = get_client()
    key = "multipart_enc"
    content_type = 'text/bla'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    init_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': kms_keyid,
        'Content-Type': content_type
    }
    part_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': kms_keyid2
    }
    resend_parts = []

    _multipart_upload_enc(client, bucket_name, key, objlen, part_size=5*1024*1024,
            init_headers=init_headers, part_headers=part_headers, metadata=metadata,
            resend_parts=resend_parts)


@attr(resource='object')
@attr(method='put')
@attr(operation='multipart KMS upload with unexistent key_id for chunks')
@attr(assertion='successful')
@attr('encryption')
def test_sse_kms_multipart_invalid_chunks_2():
    kms_keyid = get_main_kms_keyid()
    bucket_name = get_new_bucket()
    client = get_client()
    key = "multipart_enc"
    content_type = 'text/plain'
    objlen = 30 * 1024 * 1024
    metadata = {'foo': 'bar'}
    init_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': kms_keyid,
        'Content-Type': content_type
    }
    part_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': 'testkey-not-present'
    }
    resend_parts = []

    _multipart_upload_enc(client, bucket_name, key, objlen, part_size=5*1024*1024,
            init_headers=init_headers, part_headers=part_headers, metadata=metadata,
            resend_parts=resend_parts)


@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated KMS browser based upload via POST request')
@attr(assertion='succeeds and returns written data')
@attr('encryption')
def test_sse_kms_post_object_authenticated_request():
    kms_keyid = get_main_kms_keyid()
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [\
    {"bucket": bucket_name},\
    ["starts-with", "$key", "foo"],\
    {"acl": "private"},\
    ["starts-with", "$Content-Type", "text/plain"],\
    ["starts-with", "$x-amz-server-side-encryption", ""], \
    ["starts-with", "$x-amz-server-side-encryption-aws-kms-key-id", ""], \
    ["content-length-range", 0, 1024]\
    ]\
    }


    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([ ("key" , "foo.txt"),("AWSAccessKeyId" , aws_access_key_id),\
    ("acl" , "private"),("signature" , signature),("policy" , policy),\
    ("Content-Type" , "text/plain"),
    ('x-amz-server-side-encryption', 'aws:kms'), \
    ('x-amz-server-side-encryption-aws-kms-key-id', kms_keyid), \
    ('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)

    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-KMS encrypted transfer 1 byte')
@attr(assertion='success')
@attr('encryption')
def test_sse_kms_transfer_1b():
    kms_keyid = get_main_kms_keyid()
    if kms_keyid is None:
        raise SkipTest
    _test_sse_kms_customer_write(1, key_id = kms_keyid)


@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-KMS encrypted transfer 1KB')
@attr(assertion='success')
@attr('encryption')
def test_sse_kms_transfer_1kb():
    kms_keyid = get_main_kms_keyid()
    if kms_keyid is None:
        raise SkipTest
    _test_sse_kms_customer_write(1024, key_id = kms_keyid)


@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-KMS encrypted transfer 1MB')
@attr(assertion='success')
@attr('encryption')
def test_sse_kms_transfer_1MB():
    kms_keyid = get_main_kms_keyid()
    if kms_keyid is None:
        raise SkipTest
    _test_sse_kms_customer_write(1024*1024, key_id = kms_keyid)


@attr(resource='object')
@attr(method='put')
@attr(operation='Test SSE-KMS encrypted transfer 13 bytes')
@attr(assertion='success')
@attr('encryption')
def test_sse_kms_transfer_13b():
    kms_keyid = get_main_kms_keyid()
    if kms_keyid is None:
        raise SkipTest
    _test_sse_kms_customer_write(13, key_id = kms_keyid)


@attr(resource='object')
@attr(method='get')
@attr(operation='write encrypted with SSE-KMS and read with SSE-KMS')
@attr(assertion='operation fails')
@attr('encryption')
def test_sse_kms_read_declare():
    bucket_name = get_new_bucket()
    client = get_client()
    sse_kms_client_headers = {
        'x-amz-server-side-encryption': 'aws:kms',
        'x-amz-server-side-encryption-aws-kms-key-id': 'testkey-1'
    }
    data = 'A'*100
    key = 'testobj'

    client.put_object(Bucket=bucket_name, Key=key, Body=data)
    lf = (lambda **kwargs: kwargs['params']['headers'].update(sse_kms_client_headers))
    client.meta.events.register('before-call.s3.GetObject', lf)

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key=key)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)

def _create_simple_tagset(count):
    tagset = []
    for i in range(count):
        tagset.append({'Key': str(i), 'Value': str(i)})

    return {'TagSet': tagset}

def _make_random_string(size):
    return ''.join(random.choice(string.ascii_letters) for _ in range(size))


@attr(resource='object')
@attr(method='get')
@attr(operation='Test Get/PutObjTagging output')
@attr(assertion='success')
@attr('tagging')
def test_get_obj_tagging():
    key = 'testputtags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    input_tagset = _create_simple_tagset(2)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])


@attr(resource='object')
@attr(method='get')
@attr(operation='Test HEAD obj tagging output')
@attr(assertion='success')
@attr('tagging')
def test_get_obj_head_tagging():
    key = 'testputtags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()
    count = 2

    input_tagset = _create_simple_tagset(count)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.head_object(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    eq(response['ResponseMetadata']['HTTPHeaders']['x-amz-tagging-count'], str(count))

@attr(resource='object')
@attr(method='get')
@attr(operation='Test Put max allowed tags')
@attr(assertion='success')
@attr('tagging')
def test_put_max_tags():
    key = 'testputmaxtags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    input_tagset = _create_simple_tagset(10)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='Test Put max allowed tags')
@attr(assertion='fails')
@attr('tagging')
def test_put_excess_tags():
    key = 'testputmaxtags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    input_tagset = _create_simple_tagset(11)
    e = assert_raises(ClientError, client.put_object_tagging, Bucket=bucket_name, Key=key, Tagging=input_tagset)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidTag')

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test Put max allowed k-v size')
@attr(assertion='success')
@attr('tagging')
def test_put_max_kvsize_tags():
    key = 'testputmaxkeysize'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    for i in range(10):
        k = _make_random_string(128)
        v = _make_random_string(256)
        tagset.append({'Key': k, 'Value': v})

    input_tagset = {'TagSet': tagset}

    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    for kv_pair in response['TagSet']:
        eq((kv_pair in input_tagset['TagSet']), True)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test exceed key size')
@attr(assertion='success')
@attr('tagging')
def test_put_excess_key_tags():
    key = 'testputexcesskeytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    for i in range(10):
        k = _make_random_string(129)
        v = _make_random_string(256)
        tagset.append({'Key': k, 'Value': v})

    input_tagset = {'TagSet': tagset}

    e = assert_raises(ClientError, client.put_object_tagging, Bucket=bucket_name, Key=key, Tagging=input_tagset)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidTag')

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test exceed val size')
@attr(assertion='success')
@attr('tagging')
def test_put_excess_val_tags():
    key = 'testputexcesskeytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    for i in range(10):
        k = _make_random_string(128)
        v = _make_random_string(257)
        tagset.append({'Key': k, 'Value': v})

    input_tagset = {'TagSet': tagset}

    e = assert_raises(ClientError, client.put_object_tagging, Bucket=bucket_name, Key=key, Tagging=input_tagset)
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidTag')

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test PUT modifies existing tags')
@attr(assertion='success')
@attr('tagging')
def test_put_modify_tags():
    key = 'testputmodifytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    tagset = []
    tagset.append({'Key': 'key', 'Value': 'val'})
    tagset.append({'Key': 'key2', 'Value': 'val2'})

    input_tagset = {'TagSet': tagset}

    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

    tagset2 = []
    tagset2.append({'Key': 'key3', 'Value': 'val3'})

    input_tagset2 = {'TagSet': tagset2}

    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset2)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset2['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='Test Delete tags')
@attr(assertion='success')
@attr('tagging')
def test_put_delete_tags():
    key = 'testputmodifytags'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    input_tagset = _create_simple_tagset(2)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

    response = client.delete_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 204)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='post')
@attr(operation='anonymous browser based upload via POST request')
@attr('tagging')
@attr(assertion='succeeds and returns written data')
def test_post_object_tags_anonymous_request():
    bucket_name = get_new_bucket_name()
    client = get_client()
    url = _get_post_url(bucket_name)
    client.create_bucket(ACL='public-read-write', Bucket=bucket_name)

    key_name = "foo.txt"
    input_tagset = _create_simple_tagset(2)
    # xml_input_tagset is the same as input_tagset in xml.
    # There is not a simple way to change input_tagset to xml like there is in the boto2 tetss
    xml_input_tagset = "<Tagging><TagSet><Tag><Key>0</Key><Value>0</Value></Tag><Tag><Key>1</Key><Value>1</Value></Tag></TagSet></Tagging>"


    payload = OrderedDict([
        ("key" , key_name),
        ("acl" , "public-read"),
        ("Content-Type" , "text/plain"),
        ("tagging", xml_input_tagset),
        ('file', ('bar')),
    ])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key=key_name)
    body = _get_body(response)
    eq(body, 'bar')

    response = client.get_object_tagging(Bucket=bucket_name, Key=key_name)
    eq(response['TagSet'], input_tagset['TagSet'])

@attr(resource='object')
@attr(method='post')
@attr(operation='authenticated browser based upload via POST request')
@attr('tagging')
@attr(assertion='succeeds and returns written data')
def test_post_object_tags_authenticated_request():
    bucket_name = get_new_bucket()
    client = get_client()

    url = _get_post_url(bucket_name)
    utc = pytz.utc
    expires = datetime.datetime.now(utc) + datetime.timedelta(seconds=+6000)

    policy_document = {"expiration": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),\
    "conditions": [
    {"bucket": bucket_name},
        ["starts-with", "$key", "foo"],
        {"acl": "private"},
        ["starts-with", "$Content-Type", "text/plain"],
        ["content-length-range", 0, 1024],
        ["starts-with", "$tagging", ""]
    ]}

    # xml_input_tagset is the same as `input_tagset = _create_simple_tagset(2)` in xml
    # There is not a simple way to change input_tagset to xml like there is in the boto2 tetss
    xml_input_tagset = "<Tagging><TagSet><Tag><Key>0</Key><Value>0</Value></Tag><Tag><Key>1</Key><Value>1</Value></Tag></TagSet></Tagging>"

    json_policy_document = json.JSONEncoder().encode(policy_document)
    bytes_json_policy_document = bytes(json_policy_document, 'utf-8')
    policy = base64.b64encode(bytes_json_policy_document)
    aws_secret_access_key = get_main_aws_secret_key()
    aws_access_key_id = get_main_aws_access_key()

    signature = base64.b64encode(hmac.new(bytes(aws_secret_access_key, 'utf-8'), policy, hashlib.sha1).digest())

    payload = OrderedDict([
        ("key" , "foo.txt"),
        ("AWSAccessKeyId" , aws_access_key_id),\
        ("acl" , "private"),("signature" , signature),("policy" , policy),\
        ("tagging", xml_input_tagset),
        ("Content-Type" , "text/plain"),
        ('file', ('bar'))])

    r = requests.post(url, files = payload)
    eq(r.status_code, 204)
    response = client.get_object(Bucket=bucket_name, Key='foo.txt')
    body = _get_body(response)
    eq(body, 'bar')


@attr(resource='object')
@attr(method='put')
@attr(operation='Test PutObj with tagging headers')
@attr(assertion='success')
@attr('tagging')
def test_put_obj_with_tags():
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'testtagobj1'
    data = 'A'*100

    tagset = []
    tagset.append({'Key': 'bar', 'Value': ''})
    tagset.append({'Key': 'foo', 'Value': 'bar'})

    put_obj_tag_headers = {
        'x-amz-tagging' : 'foo=bar&bar'
    }

    lf = (lambda **kwargs: kwargs['params']['headers'].update(put_obj_tag_headers))
    client.meta.events.register('before-call.s3.PutObject', lf)

    client.put_object(Bucket=bucket_name, Key=key, Body=data)
    response = client.get_object(Bucket=bucket_name, Key=key)
    body = _get_body(response)
    eq(body, data)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    response_tagset = response['TagSet']
    tagset = tagset
    eq(response_tagset, tagset)

def _make_arn_resource(path="*"):
    return "arn:aws:s3:::{}".format(path)

@attr(resource='object')
@attr(method='get')
@attr(operation='Test GetObjTagging public read')
@attr(assertion='success')
@attr('tagging')
@attr('bucket-policy')
def test_get_tags_acl_public():
    key = 'testputtagsacl'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    resource = _make_arn_resource("{}/{}".format(bucket_name, key))
    policy_document = make_json_policy("s3:GetObjectTagging",
                                       resource)

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    input_tagset = _create_simple_tagset(10)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    alt_client = get_alt_client()

    response = alt_client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='Test PutObjTagging public wrote')
@attr(assertion='success')
@attr('tagging')
@attr('bucket-policy')
def test_put_tags_acl_public():
    key = 'testputtagsacl'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    resource = _make_arn_resource("{}/{}".format(bucket_name, key))
    policy_document = make_json_policy("s3:PutObjectTagging",
                                       resource)

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    input_tagset = _create_simple_tagset(10)
    alt_client = get_alt_client()
    response = alt_client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['TagSet'], input_tagset['TagSet'])

@attr(resource='object')
@attr(method='get')
@attr(operation='test deleteobjtagging public')
@attr(assertion='success')
@attr('tagging')
@attr('bucket-policy')
def test_delete_tags_obj_public():
    key = 'testputtagsacl'
    bucket_name = _create_key_with_random_content(key)
    client = get_client()

    resource = _make_arn_resource("{}/{}".format(bucket_name, key))
    policy_document = make_json_policy("s3:DeleteObjectTagging",
                                       resource)

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)

    input_tagset = _create_simple_tagset(10)
    response = client.put_object_tagging(Bucket=bucket_name, Key=key, Tagging=input_tagset)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

    alt_client = get_alt_client()

    response = alt_client.delete_object_tagging(Bucket=bucket_name, Key=key)
    eq(response['ResponseMetadata']['HTTPStatusCode'], 204)

    response = client.get_object_tagging(Bucket=bucket_name, Key=key)
    eq(len(response['TagSet']), 0)

@attr(resource='object')
@attr(method='put')
@attr(operation='test whether a correct version-id returned')
@attr(assertion='version-id is same as bucket list')
@attr('versioning')
def test_versioning_bucket_atomic_upload_return_version_id():
    bucket_name = get_new_bucket()
    client = get_client()
    key = 'bar'

    # for versioning-enabled-bucket, an non-empty version-id should return
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")
    response = client.put_object(Bucket=bucket_name, Key=key)
    version_id = response['VersionId']

    response  = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    for version in versions:
        eq(version['VersionId'], version_id)


    # for versioning-default-bucket, no version-id should return.
    bucket_name = get_new_bucket()
    key = 'baz'
    response = client.put_object(Bucket=bucket_name, Key=key)
    eq(('VersionId' in response), False)

    # for versioning-suspended-bucket, no version-id should return.
    bucket_name = get_new_bucket()
    key = 'baz'
    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")
    response = client.put_object(Bucket=bucket_name, Key=key)
    eq(('VersionId' in response), False)

@attr(resource='object')
@attr(method='put')
@attr(operation='test whether a correct version-id returned')
@attr(assertion='version-id is same as bucket list')
@attr('versioning')
def test_versioning_bucket_multipart_upload_return_version_id():
    content_type='text/bla'
    objlen = 30 * 1024 * 1024

    bucket_name = get_new_bucket()
    client = get_client()
    key = 'bar'
    metadata={'foo': 'baz'}

    # for versioning-enabled-bucket, an non-empty version-id should return
    check_configure_versioning_retry(bucket_name, "Enabled", "Enabled")

    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen, client=client, content_type=content_type, metadata=metadata)

    response = client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    version_id = response['VersionId']

    response  = client.list_object_versions(Bucket=bucket_name)
    versions = response['Versions']
    for version in versions:
        eq(version['VersionId'], version_id)

    # for versioning-default-bucket, no version-id should return.
    bucket_name = get_new_bucket()
    key = 'baz'

    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen, client=client, content_type=content_type, metadata=metadata)

    response = client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    eq(('VersionId' in response), False)

    # for versioning-suspended-bucket, no version-id should return
    bucket_name = get_new_bucket()
    key = 'foo'
    check_configure_versioning_retry(bucket_name, "Suspended", "Suspended")

    (upload_id, data, parts) = _multipart_upload(bucket_name=bucket_name, key=key, size=objlen, client=client, content_type=content_type, metadata=metadata)

    response = client.complete_multipart_upload(Bucket=bucket_name, Key=key, UploadId=upload_id, MultipartUpload={'Parts': parts})
    eq(('VersionId' in response), False)





@attr(resource='object')
@attr(method='copy')
@attr(operation='copy w/ x-amz-copy-source-if-match: the latest ETag')
@attr(assertion='succeeds')
def test_copy_object_ifmatch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    resp = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    client.copy_object(Bucket=bucket_name, CopySource=bucket_name+'/foo', CopySourceIfMatch=resp['ETag'], Key='bar')
    response = client.get_object(Bucket=bucket_name, Key='bar')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='copy')
@attr(operation='copy w/ x-amz-copy-source-if-match: bogus ETag')
@attr(assertion='fails 412')
# TODO: remove fails_on_rgw when https://tracker.ceph.com/issues/40808 is resolved
@attr('fails_on_rgw')
def test_copy_object_ifmatch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    e = assert_raises(ClientError, client.copy_object, Bucket=bucket_name, CopySource=bucket_name+'/foo', CopySourceIfMatch='ABCORZ', Key='bar')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

@attr(resource='object')
@attr(method='copy')
@attr(operation='copy w/ x-amz-copy-source-if-none-match: the latest ETag')
@attr(assertion='fails 412')
# TODO: remove fails_on_rgw when https://tracker.ceph.com/issues/40808 is resolved
@attr('fails_on_rgw')
def test_copy_object_ifnonematch_good():
    bucket_name = get_new_bucket()
    client = get_client()
    resp = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    e = assert_raises(ClientError, client.copy_object, Bucket=bucket_name, CopySource=bucket_name+'/foo', CopySourceIfNoneMatch=resp['ETag'], Key='bar')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 412)
    eq(error_code, 'PreconditionFailed')

@attr(resource='object')
@attr(method='copy')
@attr(operation='copy w/ x-amz-copy-source-if-none-match: bogus ETag')
@attr(assertion='succeeds')
def test_copy_object_ifnonematch_failed():
    bucket_name = get_new_bucket()
    client = get_client()
    resp = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    client.copy_object(Bucket=bucket_name, CopySource=bucket_name+'/foo', CopySourceIfNoneMatch='ABCORZ', Key='bar')
    response = client.get_object(Bucket=bucket_name, Key='bar')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='bucket')
@attr(method='get')
@attr(operation='Test User Policy')
@attr(assertion='succeeds')
@attr('user-policy')
def test_user_policy():
    client = get_tenant_iam_client()

    policy_document = json.dumps(
    {"Version":"2012-10-17",
     "Statement": {
         "Effect":"Allow",
         "Action":"*",
         "Resource":"*"}}
    )
    client.put_user_policy(
        PolicyDocument= policy_document,
        PolicyName='AllAccessPolicy',
        UserName=get_tenant_user_id(),
    )

@attr(resource='bucket')
@attr(method='get')
@attr(operation='get bucket policy status on a new bucket')
@attr(assertion='succeeds')
@attr('policy_status')
def test_get_bucket_policy_status():
    bucket_name = get_new_bucket()
    client = get_client()
    resp = client.get_bucket_policy_status(Bucket=bucket_name)
    eq(resp['PolicyStatus']['IsPublic'],False)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='get bucket policy status on a public acl bucket')
@attr(assertion='succeeds')
@attr('policy_status')
def test_get_public_acl_bucket_policy_status():
    bucket_name = get_new_bucket()
    client = get_client()
    client = get_client()
    client.put_bucket_acl(Bucket=bucket_name, ACL='public-read')
    resp = client.get_bucket_policy_status(Bucket=bucket_name)
    eq(resp['PolicyStatus']['IsPublic'],True)

@attr(resource='bucket')
@attr(method='get')
@attr(operation='get bucket policy status on a authenticated acl bucket')
@attr(assertion='succeeds')
@attr('policy_status')
def test_get_authpublic_acl_bucket_policy_status():
    bucket_name = get_new_bucket()
    client = get_client()
    client = get_client()
    client.put_bucket_acl(Bucket=bucket_name, ACL='authenticated-read')
    resp = client.get_bucket_policy_status(Bucket=bucket_name)
    eq(resp['PolicyStatus']['IsPublic'],True)


@attr(resource='bucket')
@attr(method='get')
@attr(operation='get bucket policy status on a public policy bucket')
@attr(assertion='succeeds')
@attr('policy_status')
def test_get_publicpolicy_acl_bucket_policy_status():
    bucket_name = get_new_bucket()
    client = get_client()
    client = get_client()

    resp = client.get_bucket_policy_status(Bucket=bucket_name)
    eq(resp['PolicyStatus']['IsPublic'],False)

    resource1 = "arn:aws:s3:::" + bucket_name
    resource2 = "arn:aws:s3:::" + bucket_name + "/*"
    policy_document = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:ListBucket",
        "Resource": [
            "{}".format(resource1),
            "{}".format(resource2)
          ]
        }]
     })

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)
    resp = client.get_bucket_policy_status(Bucket=bucket_name)
    eq(resp['PolicyStatus']['IsPublic'],True)


@attr(resource='bucket')
@attr(method='get')
@attr(operation='get bucket policy status on a public policy bucket')
@attr(assertion='succeeds')
@attr('policy_status')
def test_get_nonpublicpolicy_acl_bucket_policy_status():
    bucket_name = get_new_bucket()
    client = get_client()
    client = get_client()

    resp = client.get_bucket_policy_status(Bucket=bucket_name)
    eq(resp['PolicyStatus']['IsPublic'],False)

    resource1 = "arn:aws:s3:::" + bucket_name
    resource2 = "arn:aws:s3:::" + bucket_name + "/*"
    policy_document = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": "s3:ListBucket",
        "Resource": [
            "{}".format(resource1),
            "{}".format(resource2)
          ],
        "Condition": {
            "IpAddress":
            {"aws:SourceIp": "10.0.0.0/32"}
        }
        }]
     })

    client.put_bucket_policy(Bucket=bucket_name, Policy=policy_document)
    resp = client.get_bucket_policy_status(Bucket=bucket_name)
    eq(resp['PolicyStatus']['IsPublic'],False)


