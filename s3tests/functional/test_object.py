
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


@attr(resource='object')
@attr(method='put')
@attr(operation='non-existant bucket')
@attr(assertion='fails 404')
def test_object_write_to_nonexist_bucket():
    key_names = ['foo']
    bucket_name = 'whatchutalkinboutwillis'
    client = get_client()

    e = assert_raises(ClientError, client.put_object, Bucket=bucket_name, Key='foo', Body='foo')

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='get')
@attr(operation='read contents that were never written')
@attr(assertion='fails 404')
def test_object_read_not_exist():
    bucket_name = get_new_bucket()
    client = get_client()

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='bar')

    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

@attr(resource='object')
@attr(method='put')
@attr(operation='write zero-byte key')
@attr(assertion='correct content length')
def test_object_head_zero_bytes():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo', Body='')

    response = client.head_object(Bucket=bucket_name, Key='foo')
    eq(response['ContentLength'], 0)

@attr(resource='object')
@attr(method='put')
@attr(operation='write key')
@attr(assertion='correct etag')
def test_object_write_check_etag():
    bucket_name = get_new_bucket()
    client = get_client()
    response = client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)
    eq(response['ETag'], '"37b51d194a7513e45b56f6524f2d51f2"')

def get_http_response(**kwargs):
    global http_response
    http_response = kwargs['http_response'].__dict__

@attr(resource='object')
@attr(method='get')
@attr(operation='read contents that were never written to raise one error response')
@attr(assertion='RequestId appears in the error response')
def test_object_requestid_matches_header_on_error():
    bucket_name = get_new_bucket()
    client = get_client()

    # get http response after failed request
    client.meta.events.register('after-call.s3.GetObject', get_http_response)
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='bar')

    response_body = http_response['_content']
    resp_body_xml = ET.fromstring(response_body)
    request_id = resp_body_xml.find('.//RequestId').text

    assert request_id is not None
    eq(request_id, e.response['ResponseMetadata']['RequestId'])

def _make_objs_dict(key_names):
    objs_list = []
    for key in key_names:
        obj_dict = {'Key': key}
        objs_list.append(obj_dict)
    objs_dict = {'Objects': objs_list}
    return objs_dict

@attr(resource='object')
@attr(method='post')
@attr(operation='delete multiple objects')
@attr(assertion='deletes multiple objects with a single call')
def test_multi_object_delete():
    key_names = ['key0', 'key1', 'key2']
    bucket_name = _create_objects(keys=key_names)
    client = get_client()
    response = client.list_objects(Bucket=bucket_name)
    eq(len(response['Contents']), 3)

    objs_dict = _make_objs_dict(key_names=key_names)
    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)

    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects(Bucket=bucket_name)
    assert 'Contents' not in response

    response = client.delete_objects(Bucket=bucket_name, Delete=objs_dict)
    eq(len(response['Deleted']), 3)
    assert 'Errors' not in response
    response = client.list_objects(Bucket=bucket_name)
    assert 'Contents' not in response

def _get_body(response):
    body = response['Body']
    got = body.read()
    if type(got) is bytes:
        got = got.decode()
    return got

@attr(resource='object')
@attr(method='all')
@attr(operation='complete object life cycle')
@attr(assertion='read back what we wrote and rewrote')
def test_object_write_read_update_read_delete():
    bucket_name = get_new_bucket()
    client = get_client()

    # Write
    client.put_object(Bucket=bucket_name, Key='foo', Body='bar')
    # Read
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')
    # Update
    client.put_object(Bucket=bucket_name, Key='foo', Body='soup')
    # Read
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'soup')
    # Delete
    client.delete_object(Bucket=bucket_name, Key='foo')

@attr(resource='object')
@attr(method='put')
@attr(operation='data write from file (w/100-Continue)')
@attr(assertion='succeeds and returns written data')
def test_object_write_file():
    bucket_name = get_new_bucket()
    client = get_client()
    data_str = 'bar'
    data = bytes(data_str, 'utf-8')
    client.put_object(Bucket=bucket_name, Key='foo', Body=data)
    response = client.get_object(Bucket=bucket_name, Key='foo')
    body = _get_body(response)
    eq(body, 'bar')

@attr(resource='object')
@attr(method='get')
@attr(operation='publically readable bucket')
@attr(assertion='bucket is readable')
def test_object_raw_get():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')

    unauthenticated_client = get_unauthenticated_client()
    response = unauthenticated_client.get_object(Bucket=bucket_name, Key='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='get')
@attr(operation='deleted object and bucket')
@attr(assertion='fails 404')
def test_object_raw_get_bucket_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')
    client.delete_bucket(Bucket=bucket_name)

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='get')
@attr(operation='deleted object and bucket')
@attr(assertion='fails 404')
def test_object_delete_key_bucket_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')
    client.delete_bucket(Bucket=bucket_name)

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.delete_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='get')
@attr(operation='deleted object')
@attr(assertion='fails 404')
def test_object_raw_get_object_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

@attr(resource='object')
@attr(method='ACLs')
@attr(operation='authenticated on public bucket/private object')
@attr(assertion='succeeds')
def test_object_raw_authenticated_object_acl():
    bucket_name = _setup_bucket_object_acl('public-read', 'private')

    client = get_client()
    response = client.get_object(Bucket=bucket_name, Key='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='get')
@attr(operation='authenticated on deleted object and bucket')
@attr(assertion='fails 404')
def test_object_raw_authenticated_bucket_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')
    client.delete_bucket(Bucket=bucket_name)

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchBucket')

@attr(resource='object')
@attr(method='get')
@attr(operation='authenticated on deleted object')
@attr(assertion='fails 404')
def test_object_raw_authenticated_object_gone():
    bucket_name = _setup_bucket_object_acl('public-read', 'public-read')
    client = get_client()

    client.delete_object(Bucket=bucket_name, Key='foo')

    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 404)
    eq(error_code, 'NoSuchKey')

@attr(resource='object')
@attr(method='put')
@attr(operation='unauthenticated, no object acls')
@attr(assertion='fails 403')
def test_object_anon_put():
    bucket_name = get_new_bucket()
    client = get_client()

    client.put_object(Bucket=bucket_name, Key='foo')

    unauthenticated_client = get_unauthenticated_client()

    e = assert_raises(ClientError, unauthenticated_client.put_object, Bucket=bucket_name, Key='foo', Body='foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)
    eq(error_code, 'AccessDenied')

@attr(resource='object')
@attr(method='put')
@attr(operation='unauthenticated, publically writable object')
@attr(assertion='succeeds')
def test_object_anon_put_write_access():
    bucket_name = _setup_bucket_acl('public-read-write')
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo')

    unauthenticated_client = get_unauthenticated_client()

    response = unauthenticated_client.put_object(Bucket=bucket_name, Key='foo', Body='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)

@attr(resource='object')
@attr(method='put')
@attr(operation='authenticated, no object acls')
@attr(assertion='succeeds')
def test_object_put_authenticated():
    bucket_name = get_new_bucket()
    client = get_client()

    response = client.put_object(Bucket=bucket_name, Key='foo', Body='foo')
    eq(response['ResponseMetadata']['HTTPStatusCode'], 200)


def add_obj_user_grant(bucket_name, key, grant):
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

    response = client.get_object_acl(Bucket=bucket_name, Key=key)

    grants = response['Grants']
    grants.append(grant)

    grant = {'Grants': grants, 'Owner': {'DisplayName': main_display_name, 'ID': main_user_id}}

    return grant

@attr(resource='object.acls')
@attr(method='put')
@attr(operation='set write-acp')
@attr(assertion='does not modify other attributes')
def test_object_acl_full_control_verify_attributes():
    bucket_name = get_new_bucket_name()
    main_client = get_client()
    alt_client = get_alt_client()

    main_client.create_bucket(Bucket=bucket_name, ACL='public-read-write')

    header = {'x-amz-foo': 'bar'}
    # lambda to add any header
    add_header = (lambda **kwargs: kwargs['params']['headers'].update(header))

    main_client.meta.events.register('before-call.s3.PutObject', add_header)
    main_client.put_object(Bucket=bucket_name, Key='foo', Body='bar')

    response = main_client.get_object(Bucket=bucket_name, Key='foo')
    content_type = response['ContentType']
    etag = response['ETag']

    alt_user_id = get_alt_user_id()

    grant = {'Grantee': {'ID': alt_user_id, 'Type': 'CanonicalUser' }, 'Permission': 'FULL_CONTROL'}

    grants = add_obj_user_grant(bucket_name, 'foo', grant)

    main_client.put_object_acl(Bucket=bucket_name, Key='foo', AccessControlPolicy=grants)

    response = main_client.get_object(Bucket=bucket_name, Key='foo')
    eq(content_type, response['ContentType'])
    eq(etag, response['ETag'])

@attr(resource='object')
@attr(method='put')
@attr(operation='copy zero sized object in same bucket')
@attr(assertion='works')
def test_object_copy_zero_size():
    key = 'foo123bar'
    bucket_name = _create_objects(keys=[key])
    fp_a = FakeWriteFile(0, '')
    client = get_client()
    client.put_object(Bucket=bucket_name, Key=key, Body=fp_a)

    copy_source = {'Bucket': bucket_name, 'Key': key}

    client.copy(copy_source, bucket_name, 'bar321foo')
    response = client.get_object(Bucket=bucket_name, Key='bar321foo')
    eq(response['ContentLength'], 0)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object in same bucket')
@attr(assertion='works')
def test_object_copy_same_bucket():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}

    client.copy(copy_source, bucket_name, 'bar321foo')

    response = client.get_object(Bucket=bucket_name, Key='bar321foo')
    body = _get_body(response)
    eq('foo', body)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object with content-type')
@attr(assertion='works')
def test_object_copy_verify_contenttype():
    bucket_name = get_new_bucket()
    client = get_client()

    content_type = 'text/bla'
    client.put_object(Bucket=bucket_name, ContentType=content_type, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}

    client.copy(copy_source, bucket_name, 'bar321foo')

    response = client.get_object(Bucket=bucket_name, Key='bar321foo')
    body = _get_body(response)
    eq('foo', body)
    response_content_type = response['ContentType']
    eq(response_content_type, content_type)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object to itself')
@attr(assertion='fails')
def test_object_copy_to_itself():
    bucket_name = get_new_bucket()
    client = get_client()
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}

    e = assert_raises(ClientError, client.copy, copy_source, bucket_name, 'foo123bar')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(error_code, 'InvalidRequest')

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object from different bucket')
@attr(assertion='works')
def test_object_copy_diff_bucket():
    bucket_name1 = get_new_bucket()
    bucket_name2 = get_new_bucket()

    client = get_client()
    client.put_object(Bucket=bucket_name1, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name1, 'Key': 'foo123bar'}

    client.copy(copy_source, bucket_name2, 'bar321foo')

    response = client.get_object(Bucket=bucket_name2, Key='bar321foo')
    body = _get_body(response)
    eq('foo', body)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy to an inaccessible bucket')
@attr(assertion='fails w/AttributeError')
def test_object_copy_not_owned_bucket():
    client = get_client()
    alt_client = get_alt_client()
    bucket_name1 = get_new_bucket_name()
    bucket_name2 = get_new_bucket_name()
    client.create_bucket(Bucket=bucket_name1)
    alt_client.create_bucket(Bucket=bucket_name2)

    client.put_object(Bucket=bucket_name1, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name1, 'Key': 'foo123bar'}

    e = assert_raises(ClientError, alt_client.copy, copy_source, bucket_name2, 'bar321foo')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 403)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy a non-owned object in a non-owned bucket, but with perms')
@attr(assertion='works')
def test_object_copy_not_owned_object_bucket():
    client = get_client()
    alt_client = get_alt_client()
    bucket_name = get_new_bucket_name()
    client.create_bucket(Bucket=bucket_name)
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    alt_user_id = get_alt_user_id()

    grant = {'Grantee': {'ID': alt_user_id, 'Type': 'CanonicalUser' }, 'Permission': 'FULL_CONTROL'}
    grants = add_obj_user_grant(bucket_name, 'foo123bar', grant)
    client.put_object_acl(Bucket=bucket_name, Key='foo123bar', AccessControlPolicy=grants)

    grant = add_bucket_user_grant(bucket_name, grant)
    client.put_bucket_acl(Bucket=bucket_name, AccessControlPolicy=grant)

    alt_client.get_object(Bucket=bucket_name, Key='foo123bar')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
    alt_client.copy(copy_source, bucket_name, 'bar321foo')

@attr(resource='object')
@attr(method='put')
@attr(operation='copy object and change acl')
@attr(assertion='works')
def test_object_copy_canned_acl():
    bucket_name = get_new_bucket()
    client = get_client()
    alt_client = get_alt_client()
    client.put_object(Bucket=bucket_name, Key='foo123bar', Body='foo')

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
    client.copy_object(Bucket=bucket_name, CopySource=copy_source, Key='bar321foo', ACL='public-read')
    # check ACL is applied by doing GET from another user
    alt_client.get_object(Bucket=bucket_name, Key='bar321foo')


    metadata={'abc': 'def'}
    copy_source = {'Bucket': bucket_name, 'Key': 'bar321foo'}
    client.copy_object(ACL='public-read', Bucket=bucket_name, CopySource=copy_source, Key='foo123bar', Metadata=metadata, MetadataDirective='REPLACE')

    # check ACL is applied by doing GET from another user
    alt_client.get_object(Bucket=bucket_name, Key='foo123bar')

@attr(resource='object')
@attr(method='put')
@attr(operation='copy from non-existent bucket')
def test_object_copy_bucket_not_found():
    bucket_name = get_new_bucket()
    client = get_client()

    copy_source = {'Bucket': bucket_name + "-fake", 'Key': 'foo123bar'}
    e = assert_raises(ClientError, client.copy, copy_source, bucket_name, 'bar321foo')
    status = _get_status(e.response)
    eq(status, 404)

@attr(resource='object')
@attr(method='put')
@attr(operation='copy from non-existent object')
def test_object_copy_key_not_found():
    bucket_name = get_new_bucket()
    client = get_client()

    copy_source = {'Bucket': bucket_name, 'Key': 'foo123bar'}
    e = assert_raises(ClientError, client.copy, copy_source, bucket_name, 'bar321foo')
    status = _get_status(e.response)
    eq(status, 404)

@attr(resource='object')
@attr(method='get')
@attr(operation='read to invalid key')
@attr(assertion='fails 400')
# TODO: results in a 404 instead of 400 on the RGW
@attr('fails_on_rgw')
def test_object_read_unreadable():
    bucket_name = get_new_bucket()
    client = get_client()
    e = assert_raises(ClientError, client.get_object, Bucket=bucket_name, Key='\xae\x8a-')
    status, error_code = _get_status_and_error_code(e.response)
    eq(status, 400)
    eq(e.response['Error']['Message'], 'Couldn\'t parse the specified URI.')


