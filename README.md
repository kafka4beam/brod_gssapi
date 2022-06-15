brod_gssapi
=====

`brod_gssapi` is an authentication backend for
[brod](https://github.com/kafka4beam/brod). `brod_gssapi` makes it possible to
connect Brod to a Kafka cluster using the
[SASL/GSSAPI (Kerberos) authentication method](https://docs.confluent.io/platform/current/kafka/authentication_sasl/authentication_sasl_gssapi.html).
Please see the configuration section below for information about which Kafka
handshake versions that are supported. `brod_gssapi` uses
[sasl_auth](https://github.com/kafka4beam/sasl_auth), which is an Erlang wrapper
for a SASL/GSSAPI C library. 

Usage
-----

1. Install the dependencies for `sasl_auth`. More information about
   `sasl_auth`'s dependencies can be found in [`sasl_auth`'s README.md file](https://github.com/kafka4beam/sasl_auth).
2. Add `brod_gssapi` as dependency to your top level project that uses `brod`.
3. Add `{sasl, {callback, brod_gssapi, {gssapi, Keytab, Principal}}}` to the
   brod client config. `Keytab` should be the keytab file path, and `Principal`
   should be a byte list or binary string.

The `example/` directory in this repository contains a `docker-compose` project
with Kerberos, Zookeeper, Kafka (with SASL/GSSAPI Kerberos authentication)
and a Brod client. The `example/README.md` file describes how to run this
example. The code in `example/brod_client/src/example.erl` sets up a Brod
client with SASL/GSSAPI (Kerberos) authentication and sends and receives
messages. 


Dependencies
------------

Please see [`sasl_auth`'s README.md file](https://github.com/kafka4beam/sasl_auth)
for information about what software you need to install before compiling and
using this plugin.

Compile
-----

    $ rebar3 compile


Test
-----

    $ rebar3 ct

The example in the `example/` directory also works as a test case. The
`example/README.md` file describes how to run the example.

Configuration
-------------

For version of Brod before 3.16.4 the handshake version used for authentication
with Kafka is not passed down to the `brod_gssapi` plugin. By default,
`brod_gssapi` will use the `legacy` handshake version (the version used
before handshake version naming was introduced to Kafka). This can be changed
by configuring `brod_gssapi` with the setting `default_handshake_vsn`.
`brod_gssapi` currently only supports the `legacy` and `1` handshake versions. Handshake
version `0` is currently not supported. The setting can be changed both
programmatically with `application:set_env(brod_gssapi, default_handshake_vsn, 1)`
and by giving the following parameter to the Erlang command
`-brod_gssapi default_handshake_vsn 1`.


