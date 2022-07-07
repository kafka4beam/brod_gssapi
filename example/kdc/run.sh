#!/bin/sh



kdb5_util -P confluent -r TEST.CONFLUENT.IO create -s


echo STARTING KDC
/usr/sbin/krb5kdc -n
