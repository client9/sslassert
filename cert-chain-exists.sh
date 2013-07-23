#!/bin/bash

# https://github.com/client9/ssl-unit-tests
#

# checker to see if certificate chain exists.  This is mostly an issue
# for nginx which requires all certs to be in one file (vs. Apache
# were it's explicitly specified).  99.9% of all SSL websites use a
# chain.  for some reason https://www.yahoo.com does not.
#
#
# see the "SSL certificate chains" in
# http://nginx.org/en/docs/http/configuring_https_servers.html
#

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where
# 443 is assumed)
#
export HOSTPORT="$1"
if [[ "$HOSTPORT" != *:* ]]; then
export HOSTPORT=${HOSTPORT}:443
fi

# echo "/"
#   requests the path "/"
# openssl s_client -showcerts -connect
#   s_client    use sample SSL client
#   -showcerts  display each cert in the chain
#   -connect    effectively does this request "https://$hostport/"
# 2> /dev/null    send all noise to the black hole
# | grep 'BEGIN CERTIFICATE'
#    with -showcerts option, each certificate is printed
# | wc -l
#    count them
# | tr -d ' '
#    strip spaces, since I like being neat and tidy
#    this is needed for Mac OSX / BSD(?) `wc -l`
#
export numcerts=`echo / | openssl s_client -showcerts -connect $HOSTPORT 2> /dev/null | grep 'BEGIN CERTIFICATE' | wc -l |  tr -d ' '`

if [ "$numcerts" -lt 2 ]; then
    # only 1 cert in chain?
    #  probably wrong unless you are yahoo.com
    echo "Certificate Chain Length $numcerts < 2: FAIL"
    exit 1;
else
    # at least two certs means we have a chain.  Good.
    echo "Certificate Chain Length $numcerts >= 2: OK"
    exit 0
fi
