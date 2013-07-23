#!/bin/bash
#
# Sample to see how this works
#
source https-unit-tests.sh

export HOSTPORT=libinjection.client9.com:443
export URLPATH=/

# pull in base recommendations
recommendation-ssllabs

# only IE6 and some dumb phones use ssl-v3
protocol-ssl-v3      off

# don't include self-signed certs
self-signed-certificates-in-chain off

# make sure we make the chain correctly for nginx
minimum-certificate-chain-length    2

# slow, and only used by IE6
# note: 3DES is still FIPS compliant!
triple-des-cipher-suites off
