#!/bin/sh
#
# Sample to see how this works
#

export HOSTPORT=libinjection.client9.com:443
export URLPATH=/

source ./sslassert.sh

echo ""

recommendation_ssllabs

# only IE6 and some dumb phones use ssl_v3
sslassert "protocol-SSL-v3            = off"
sslassert "certificate-chain-length -gt 1"
sslassert "crypto-camellia            = off"
sslassert "crypto-3des                = off"
sslassert "crypto-md5                 = off"
sslassert "beast-attack               = off"

echo ""

