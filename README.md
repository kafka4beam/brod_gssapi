brod_gssapi
=====

brod_gssapi is an authentication backend for brod (https://github.com/klarna/brod),
based on sasl_auth wrapper (https://github.com/ElMaxo/sasl_auth). Just specify brod_gssapi
as an authentication backend for brod and pass your credentials to it

Build
-----

    $ rebar3 compile


Configuration
-------------

For version of brod before 3.16.4 the handshake version used for authentication
with Kafka is not passed down to the `brod_gssapi` plugin. By default,
`brod_gssapi` will use the `legacy` handshake version (the version used
before handshake version naming was introduced to Kafka). This can be changed
by configuring `brod_gssapi` with the setting `default_handshake_vsn`.
`brod_gssapi` currently only supports the `legacy` and `1` handshake versions. Handshake
version `0` is currently not supported. The setting can be changed both
programmatically with `application:set_env(brod_gssapi, default_handshake_vsn, 1)`
and by giving the following parameter to the Erlang command
`-brod_gssapi default_handshake_vsn 1`.


