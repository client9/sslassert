#!/bin/sh
export SSLASSERT_DEBUG=1
export HOSTPORT="${1}"

source ./sslassert.sh
sslassert_init

#echo "$SSLFACTS"
