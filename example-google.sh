#!/bin/sh
#
# Sample to see how this works
#
export HOSTPORT=www.google.com
export URLPATH=/

source sslassert.sh

sslassert 'secure-renegotiation               = on'
sslassert 'compression                        = off'
sslassert 'certificate-length                 = 1024'
sslassert 'protocol-ssl-v2                    = off'
sslassert 'protocol-ssl-v3                    = on'
sslassert 'protocol-tls-v10                   = on'
sslassert 'protocol-tls-v11                   = on'
sslassert 'protocol-tls-v12                   = on'
sslassert 'crypto-weak                        = off'
sslassert 'crypto-camellia                    = off'
sslassert 'crypto-idea                        = off'
sslassert 'crypto-sha160                      = on'
sslassert 'crypto-md5                         = on'
sslassert 'crypto-forward-secrecy             = on'
sslassert 'beast-attack                       = off'
sslassert 'certificate-chain-length         -gt 1'

exit $SSLASSERT_EXIT
