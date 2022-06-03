#!/bin/sh

rebar3 clean
rebar3 compile

erl -noshell `rebar3 path | xargs -n1 echo -pa | tr '\n' ' '` -eval 'example:main([])'

rebar3 clean

rm -rf _build
