#!/bin/sh


if [ "$1" != "" ]
then
    echo "USING CONFIG $1"
    rm rebar.lock
    cp "$1" rebar.config
fi

rm -rf _build
rebar3 clean
rebar3 compile

erl -noshell `rebar3 path | xargs -n1 echo -pa | tr '\n' ' '` -eval 'example:main([])'

rebar3 clean

rm -rf _build

if [ "$1" != "" ]
then
    git checkout rebar.config    
    git checkout rebar.lock    
fi
