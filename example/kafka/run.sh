#!/bin/sh


cd /opt/kafka

export KAFKA_OPTS='-Djava.security.auth.login.config=/opt/kafka/config/kafka_server_jaas.conf -Dsun.security.krb5.debug=true'

./bin/kafka-server-start.sh /opt/kafka/config/server.properties
