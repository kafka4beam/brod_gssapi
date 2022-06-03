Kerberos Kafka Brod Setup
-------------------------

## Acknowledgment

* Some of the code in this repo is copied from https://github.com/Accenture/reactive-interaction-gateway/tree/kafka-sasl-kerberos-authentication/examples/api-gateway/kafka-kerberos (which gives credits to [Dabz/kafka-security-playbook](https://github.com/Dabz/kafka-security-playbook/tree/master/kerberos))

## Requirements

* docker
* docker-compose

## How to Use

Set up Kerberos, Zookeeper and Kafka in Docker containers:

```shell
./up
```

Test that everything is working after running `./up`:

```shell
./test_send_receive.sh
# The following sends recevies messages with brod using the
# brod_gssapi plugin in the parent directory to do Kerberos
# authentication
./test_send_receive_erlang.sh
```

Stop Docker containers:

```shell
./down
```

