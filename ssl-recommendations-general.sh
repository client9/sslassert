#!/bin/sh
#
# General recommedations
#
#
export HOSTPORT=$1

source sslassert.sh

sslassert 'secure-renegotiation       = on'
sslassert 'protocol-ssl-v2            = off'
sslassert 'protocol-tls-v10           = on'
sslassert 'crypto-weak                = off'
sslassert 'compression                = off'
sslassert 'beast-attack               = off'
sslassert 'certificate-length       -ge 1024'
sslassert "certificate-chain-length -gt 1"

exit $SSLASSERT_EXIT
