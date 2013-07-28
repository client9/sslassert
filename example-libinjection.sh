#!/bin/sh
#
# Sample to see how this works
#

export HOSTPORT=libinjection.client9.com:443
export URLPATH=/

source ./sslassert.sh

echo ""
sslassert "protocol-ssl-v2            = off"
sslassert "protocol-SSL-v3            = off"
sslassert "protocol-tls-v10           = on"
sslassert "protocol-tls-v11           = on"
sslassert "protocol-tls-v12           = on"
sslassert "certificate-chain-length -gt 1"
sslassert "crypto-weak                = off"
sslassert "crypto-null                = off"
sslassert "crypto-adh                 = off"
sslassert "crypto-camellia            = off"
sslassert "crypto-seed                = off"
sslassert "crypto-idea                = off"
sslassert "crypto-3des                = off"
sslassert "crypto-md5                 = off"
sslassert 'crypto-winxp-ie-compatible = on'
sslassert "beast-attack               = off"
sslassert "self-signed-certificates-in-chain = off"

echo ""
#echo "$SSLFACTS"

exit $SSLFACTS_EXIT

