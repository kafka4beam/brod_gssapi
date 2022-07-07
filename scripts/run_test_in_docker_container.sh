#!/usr/bin/env bash

export DOCKER_BUILDKIT=1

if [ -z ${BROD_GSSAPI_DOCKER_FILE+x} ]
then
    BROD_GSSAPI_DOCKER_FILE=example/image/Dockerfile
fi

BROD_GSSAPI_DOCKER_IMAGE="brod_gssapi_`basename $BROD_GSSAPI_DOCKER_FILE`:latest"
BROD_GSSAPI_DOCKER_IMAGE=`echo $BROD_GSSAPI_DOCKER_IMAGE | tr '[:upper:]' '[:lower:]'`

docker run --rm \
-v $(pwd):/brod_gssapi \
-w /brod_gssapi \
$BROD_GSSAPI_DOCKER_IMAGE \
rebar3 ct
