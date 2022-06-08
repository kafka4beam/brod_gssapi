#!/usr/bin/env bash

set -xe

echo CREATEING TEST TOPIC

./create_test_topic.sh > /dev/null 2>&1

echo RUNNING BROD CLIENT

docker-compose exec -T brod_client ./compile_run.sh "$@"| tee brod_client.out

cat brod_client.out | grep SUCCESS

RESULT=$?

rm brod_client.out

exit $RESULT
