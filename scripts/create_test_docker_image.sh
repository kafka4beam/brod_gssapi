#!/usr/bin/env bash

export DOCKER_BUILDKIT=1

if [ -z ${BROD_GSSAPI_DOCKER_FILE+x} ]
then
    BROD_GSSAPI_DOCKER_FILE=example/image/Dockerfile
fi

BROD_GSSAPI_DOCKER_IMAGE="brod_gssapi_`basename $BROD_GSSAPI_DOCKER_FILE`:latest"
BROD_GSSAPI_DOCKER_IMAGE=`echo $BROD_GSSAPI_DOCKER_IMAGE | tr '[:upper:]' '[:lower:]'`

DOCKER_FILE_DIR=`dirname $BROD_GSSAPI_DOCKER_FILE`
DOCKER_FILE_NAME=`basename $BROD_GSSAPI_DOCKER_FILE`

cd $DOCKER_FILE_DIR

docker build -f $DOCKER_FILE_NAME -t $BROD_GSSAPI_DOCKER_IMAGE .
