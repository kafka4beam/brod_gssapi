#!/usr/bin/env bash

# Remove topic if it was created before

docker exec client bash -c "kinit -k -t /var/lib/secret/kafka-admin.key admin/for-kafka && bin/kafka-topics.sh --bootstrap-server kafka:9093 --command-config /opt/kafka/config/command.properties --delete --topic mytest"

# Create topic

docker exec client bash -c "kinit -k -t /var/lib/secret/kafka-admin.key admin/for-kafka && bin/kafka-topics.sh --bootstrap-server kafka:9093 --command-config /opt/kafka/config/command.properties --create --topic mytest"
