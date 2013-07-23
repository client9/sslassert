#!/bin/bash

# HEY YOU!!
# In no way, is this endorsed by Qualys or ssllabs.com
#
# This does attempt to match their recommendations
#

#
# should be in form of "host.fqdn.com:###" or "host.fqdn.com" (where
# 443 is assumed)
#
export HOSTPORT="$1"
if [[ "$HOSTPORT" != ":" ]]
then
export HOSTPORT=${HOSTPORT}:443
fi

echo ""
echo "ssl-unit-tests"
echo "https://github.com/client9/ssl-unit-tests"
echo ""
echo "This is not endorsed or recommended by Qualys or ssllabs"
echo "See https://www.ssllabs.com/ for current recommendations"
echo ""

CODE=0
for test in cert-chain-exists.sh \
    compression-is-off.sh secure-renegotiation-is-on.sh \
    weak-cipher-suites-are-rejected.sh \
    sslv2-is-off.sh tls10-is-on.sh tls11-is-on.sh tls12-is-on.sh;
do
    ./${test} ${HOSTPORT}
    if [ "$?" -ne "0" ]; then
       CODE=1
    fi
done

echo ""
exit $CODE
