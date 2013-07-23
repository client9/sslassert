#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

#
# SSL v3 is only required for IE6 and some other very old
# mobile devices.
#

export EXPECTED="$1"

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where 443 is assumed)
# ":443" is mandatory (or another port)
#
export HOSTPORT="$2"
if [[ "$HOSTPORT" != *:* ]]; then
export HOSTPORT=${HOSTPORT}:443
fi

#
# connect to 'https://$HOSTPORT/' using sslv2 only
#
echo / | openssl s_client -ssl3 -connect $HOSTPORT 2> /dev/null > /dev/null

if [ "$?" -eq "1" ]; then
    ACTUAL="off"
else
    ACTUAL="on"
fi

if [ "$EXPECTED" == "$ACTUAL" ]; then
    echo "SSL v3 is $ACTUAL: OK"
    exit 0
else
    echo "SSL v3 is $ACTUAL: FAIL"
    exit 1
fi
