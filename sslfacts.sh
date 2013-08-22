#!/bin/sh
export SSLASSERT_DEBUG=1

export HOSTPORT="${1}"
if [[ "${HOSTPORT}" != *:* ]]; then
    export HOSTPORT="${HOSTPORT}:443"
fi

else:
# overide using env variable
# export URLPATH=/
#export URLPATH="/\n"

source ./sslassert.sh

