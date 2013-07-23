#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

#
# Weak keys should be rejected
#

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where 443 is assumed)
# ":443" is mandatory (or another port)
#
export HOSTPORT="$1"
if [[ "$HOSTPORT" != *:* ]]; then
export HOSTPORT=${HOSTPORT}:443
fi

WEAK="0"
for CIPHER in EXP-RC4-MD5 DES-CBC-SHA EXP-DES-CBC-SHA EXP-RC2-CBC-MD5; do
    echo / | openssl s_client -cipher ${CIPHER} -quiet -connect $HOSTPORT 2>/dev/null > /dev/null
    if [ "$?" -eq "0" ]; then
        echo "Weak cipher suite $CIPHER is accepted: FAIL"
        WEAK="1"
    else
        echo "Weak cipher suite $CIPHER is rejected: OK"
    fi
done

if [ "$WEAK" -eq "0" ]; then
    echo "Weak cipher suites are rejected: OK"
    exit 0
else
    echo "Weak cipher suites are accepted: FAIL"
    exit 1
fi
