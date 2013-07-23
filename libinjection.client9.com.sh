#!/bin/bash
#
# Sample to see how this works
#
source https-unit-tests.sh

export HOSTPORT=libinjection.client9.com:443
export URLPATH=/

# pull in base recommendations
recommendation-ssllabs

# don't include self-signed certs
self-signed-certificates-in-chain off

# make sure we make the chain correctly for nginx
minimum-certificate-chain-length    2
