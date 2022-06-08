#!/usr/bin/env bash

set -xe

echo CREATEING TEST TOPIC

./create_test_topic.sh > /dev/null 2>&1

# Send MESSAGE

docker-compose exec -T client bash -c 'kinit -k -t /var/lib/secret/rig.key rig && echo "hello world, a message is sent to mytest" | ./bin/kafka-console-producer.sh --broker-list kafka:9093 --topic mytest --producer.config /opt/kafka/config/producer.properties'


# Receive MESSAGE

RES=`docker-compose exec -T client bash -c 'kinit -k -t /var/lib/secret/rig.key rig && ./bin/kafka-console-consumer.sh --bootstrap-server kafka:9093 --topic mytest --consumer.config /opt/kafka/config/consumer.properties --from-beginning --max-messages 1'`


echo $RES
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color
((echo $RES | grep "hello world") && printf "\n\n\n${GREEN}SUCCESS:${NC} Kafka and Kerberos Works!\n\n\n") || (printf "\n\n\n${RED}FAIL:${NC} Something is broken\n\n\n" ; exit 1)
