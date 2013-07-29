#!/bin/sh
export SSLASSERT_DEBUG=1
export HOSTPORT="${1}:443"

# overide using env variable
# export URLPATH=/

echo "https://${HOSTPORT}${URLPATH}"

source ./sslassert.sh

