#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

#
# Server-based secure renegotiation should be n
#

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where 443 is assumed)
# ":443" is mandatory (or another port)
#
export HOSTPORT="$1"
if [[ "$HOSTPORT" != *:* ]]; then
export HOSTPORT=${HOSTPORT}:443
fi


echo / | openssl s_client -connect $HOSTPORT 2> /dev/null | grep -i -q 'Secure Renegotiation IS supported'

# grep $? is
#     0     One or more lines were selected.
#     1     No lines were selected.
#     >1    An error occurred.

if [ "$?" -eq "0" ]; then
    echo "Secure Renegotiation is on: OK"
    exit 0
else
    echo "Secure Renegotiation is off: FAIL"
    exit 1
fi
