#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

# TLS v1.0 / SSL v3.0 is supported.
#

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where 443 is assumed)
# ":443" is mandatory (or another port)
#
export HOSTPORT="$1"
if [[ "$HOSTPORT" != *:* ]]; then
export HOSTPORT=${HOSTPORT}:443
fi

#
# connect to 'https://$HOSTPORT/' using tls 1.1
#
echo / | openssl s_client -tls1_1 -connect $HOSTPORT 2> /dev/null > /dev/null

if [ "$?" -eq "0" ]; then
  echo "TLS v1.1 is on: OK"
  exit 0
else
  echo "TLS v1.1 is off: FAIL"
  exit 1
fi
