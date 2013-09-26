#!/bin/sh
#
# Sample to see how this works
#
export HOSTPORT=www.google.com
export URLPATH=/

source ./sslassert.sh
sslassert_init

sslassert 'secure-renegotiation               = on'
sslassert 'compression                        = off'
sslassert 'certificate-length              -eq 1024'
sslassert 'protocol-ssl-v2                    = off'
sslassert 'protocol-ssl-v3                    = on'
sslassert 'protocol-tls-v10                   = on'
sslassert 'protocol-tls-v11                   = on'
sslassert 'protocol-tls-v12                   = on'
sslassert 'protocol-tls12-suite-allowed-on-tls10 = off'
sslassert "crypto-suite-count                     -eq 17"
sslassert "cipher-suite-ECDHE-RSA-AES128-GCM-SHA256 = on"
sslassert "cipher-suite-ECDHE-RSA-AES256-GCM-SHA384 = on"
sslassert "cipher-suite-ECDHE-RSA-AES128-SHA256     = on"
sslassert "cipher-suite-ECDHE-RSA-AES256-SHA384     = on"
sslassert "cipher-suite-ECDHE-RSA-RC4-SHA           = on"

sslassert "cipher-suite-ECDHE-RSA-AES128-SHA        = on"
sslassert "cipher-suite-ECDHE-RSA-AES256-SHA        = on"
sslassert "cipher-suite-ECDHE-RSA-DES-CBC3-SHA      = on"

sslassert "cipher-suite-AES128-GCM-SHA256           = on"
sslassert "cipher-suite-AES256-GCM-SHA384           = on"
sslassert "cipher-suite-AES128-SHA256               = on"
sslassert "cipher-suite-AES256-SHA256               = on"

sslassert "cipher-suite-RC4-SHA                     = on"
sslassert "cipher-suite-AES128-SHA                  = on"
sslassert "cipher-suite-AES256-SHA                  = on"
sslassert "cipher-suite-DES-CBC3-SHA                = on"

sslassert 'cipher-suite-RC4-MD5                     = on'

sslassert 'crypto-weak                        = off'
sslassert 'crypto-null                        = off'
sslassert 'crypto-adh                         = off'
sslassert 'crypto-camellia                    = off'
sslassert 'crypto-idea                        = off'
sslassert 'crypto-seed                        = off'
sslassert 'crypto-sha160                      = on'
sslassert 'crypto-md5                         = on'
sslassert 'crypto-gcm                         = on'
sslassert 'crypto-winxp-ie-compatible         = on'
sslassert 'crypto-forward-secrecy             = on'
sslassert 'beast-attack                       = off'
sslassert 'certificate-chain-length         -gt 1'

exit $SSLASSERT_EXIT
