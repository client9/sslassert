#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

# TLS v1.2 is supported
#

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where 443 is assumed)
# ":443" is mandatory (or another port)
#
export HOSTPORT="$1"
if [[ "$HOSTPORT" != ":" ]]
then
export HOSTPORT=${HOSTPORT}:443
fi

#
# connect to 'https://$HOSTPORT/' using tls 1.2
#
echo / | openssl s_client -tls1_2 -connect $HOSTPORT 2> /devnull > /dev/null

if [ "$?" -eq "0" ]; then
  # ok
  echo "TLS v1.2 is on: OK"
  exit 0
else
  # fail
  echo "TLS v1.2 is off: FAIL"
  exit 1
fi