#!/bin/sh
export SSLASSERT_DEBUG=1
export HOSTPORT="${1}:443"
export URLPATH=/
echo "https://${HOSTPORT}${URLPATH}"

source https-unit-tests.sh

