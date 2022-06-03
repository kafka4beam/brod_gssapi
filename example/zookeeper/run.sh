#!/bin/sh


export KAFKA_OPTS=-Djava.security.auth.login.config=/opt/kafka/config/zookeeper_server_jaas.conf

cd /opt/kafka

./bin/zookeeper-server-start.sh /opt/kafka/config/zookeeper.properties
