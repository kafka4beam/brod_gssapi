SASL GSSAPI Kerberos Kafka Brod Setup with `brod_gssapi`
------------------------------------------------------

## Requirements

* docker
* docker-compose

## How to Use

Set up Kerberos, Zookeeper, Kafka and clients in Docker containers:

```shell
./up
```

Test that Kafka is setup with Kerberos authentication (You need to run `./up`
first to start the containers):

```shell
./test_send_receive.sh
```

Use a brod client with the brod_gssapi plugin to do Kerberos authentication and
send and receive messages.

```shell
# Use brod version 3.16.3
./test_send_receive_erlang.sh

# Use brod master branch:
./test_send_receive_erlang.sh rebar.config_brod_master

# Use latest version of brod:
./test_send_receive_erlang.sh rebar.config_brod_latest

# Test with a custom rebar.config by creating a file with your custom config in
# ./brod_client/ and use the config by running:
./test_send_receive_erlang.sh rebar.config_the_name_of_your_custom_rebar_config_file
```

Stop the Docker containers:

```shell
./down
```

## Acknowledgment

Some of the code in this directory is copied from https://github.com/Accenture/reactive-interaction-gateway/tree/kafka-sasl-kerberos-authentication/examples/api-gateway/kafka-kerberos (which gives credits to [Dabz/kafka-security-playbook](https://github.com/Dabz/kafka-security-playbook/tree/master/kerberos))

