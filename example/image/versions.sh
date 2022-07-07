#!/bin/bash -e

# This file was taken from: https://github.com/vdesabou/kafka-docker-playground/

MAJOR_VERSION=$(echo "$KAFKA_VERSION" | cut -d. -f1)
export MAJOR_VERSION

MINOR_VERSION=$(echo "$KAFKA_VERSION" | cut -d. -f2)
export MINOR_VERSION
