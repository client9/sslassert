#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

#
# SSL Compression should be off, due to various attacks.
#

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where 443 is assumed)
# ":443" is mandatory (or another port)
#
export HOSTPORT="$1"
if [[ "$HOSTPORT" != *:* ]]; then
export HOSTPORT=${HOSTPORT}:443
fi


echo / | openssl s_client -connect $HOSTPORT 2> /dev/null | grep 'self signed certificate in certificate chain'

# grep $? is
#     0     One or more lines were selected.
#     1     No lines were selected.
#     >1    An error occurred.


if [ "$?" -eq "1" ]; then
    echo "Certificate chain has no self-signed certificates: OK"
    exit 0
else
    # didn't find "Compression: NONE" so it must be on
    echo "Certificate chain has self-signed certificates: FAIL"
    exit 1
fi
