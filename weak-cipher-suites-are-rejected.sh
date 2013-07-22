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
if [[ "$HOSTPORT" != ":" ]]
then
export HOSTPORT=${HOSTPORT}:443
fi

WEAK="0"
for CIPHER in EXP-RC4-MD5 DES-CBC-SHA EXP-DES-CBC-SHA EXP-RC2-CBC-MD5; do
    echo / | openssl s_client -cipher ${CIPHER} -quiet -connect $HOSTPORT 2>1 > /dev/null
    if [ "$?" -eq "0" ]; then
        echo "$CIPHER : Accepted (FAIL)"
        WEAK="1"
    else
        echo "$CIPHER: Rejected (OK)"
    fi
done

if [ "$WEAK" -eq "0" ]; then
    echo "Weak Cipher Suites are Not Accepted: OK"
    exit 0
else
    echo "Weak Cipher Suites are Accepted: FAIL"
    exit 1
fi
