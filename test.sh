#!/bin/bash
S3TEST_CONF=./s3tests.conf
ROOT_PATH=`pwd`
source "${ROOT_PATH}/virtualenv/bin/activate"
NOSE_BIN=

#BUCKET
nosetests s3tests.functional.test_s3:test_bucket_create_naming_bad_punctuation
nosetests s3tests.functional.test_s3:test_bucket_list_empty

#OBJECT

deactivate
