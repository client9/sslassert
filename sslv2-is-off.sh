#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

# SSL v2 has been obsoleted since 1996. It should not be accepted.
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
# connect to 'https://$HOSTPORT/' using sslv2 only
#
echo / | openssl s_client -ssl2 -connect $HOSTPORT 2> /dev/null > /dev/null

if [ "$?" -eq "1" ]; then
  # we could NOT connect, sslv2 is off, good
    echo "SSL v2 is off: OK"
    exit 0
else
    # we connected under SSLv2, fail
    echo "SSL v2 is on: FAIL"
    exit 1
fi
