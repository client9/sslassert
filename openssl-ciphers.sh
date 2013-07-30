#!/bin/sh

if [ "$OPENSSL" = "" ]; then
    OPENSSL="openssl"
fi

function suites {
TAG=$1
if [ "$SUITES" = "" ]; then
   SUITES=$1
else
  SUITES="${SUITES}:$1"
fi
echo `${OPENSSL} ciphers -v "${SUITES}" | wc -l` $SUITES
echo ""
#openssl ciphers -v "${SUITES}" | sort
}

GREP=""
function suites2 {
TAG=$1
if [ "$GREP" = "" ]; then
   GREP="$TAG"
else
   GREP="${GREP}|${TAG}"
fi
echo `${OPENSSL} ciphers -v "${SUITES}" | grep -v -E "${GREP}" | wc -l` $SUITES "| grep -v -E $GREP"
echo ""
}


echo "The default set of cipher suites."
suites "ALL"

echo "There are some extra ciphers as well."
echo "Depending on your version of openssl some of these may be in the 'ALL' as well."
suites "COMPLEMENTOFALL"

echo "Removing NULL ciphers that off no encryption.  These should be off by default"
suites "!NULL"

echo "Removing Anonymous Diffe-Hellman.  This oddly on if you select 'HIGH'"
suites "!aNULL"

echo "Removing 'export' cryptography, aka weak-cryptography using 40 and 56 bit keys"
suites "!EXPORT"

echo "Removing plain DES cryptography (3DES ok)"
suites "!DES"

echo "Removing RC2 cryptography, deprecated, SSLv2"
suites "!RC2"

echo "Removing SEED, deprecated"
suites "!SEED"

echo "Removing IDEA, deprecated"
suites "!IDEA"

echo "Removing MD5, deprecated"
suites "!MD5"

echo "Removing CAMELLIA, not needed for SSL"
suites "!CAMELLIA"

echo "Removing PreShared Keys suites"
suites "!PSK"

echo "Removing Kerberos"
suites "!KRB5"

echo "Removing SRP key exchange. Originally designed to work around RSA patents.:"
suites '!SRP'

#echo "Removing Old Ephemeral DH key agreement 'EDH-'.  Very slow, poor cipher support  and other alternatives exist now"
#suites "!kEDH"

echo "Removing Au=DSS, requires cert you don't have"
suites '!DSS'

echo "Removing Au-ECDSA-, it requires a special certificate that you don't have"
suites '!ECDSA'

echo "Unfortunately, this as far as we can go using the OpenSSL tokens."
echo "Need to grep out what we want"


echo "Removing ECDH-, not needed as ECDHE is likely a better choice if using DH"
suites2 'ECDH-'



#echo "Removing oddsball ECDHE-RSA-DES-CBC3-SHA."
#echo "I'm not sure how it would ever be selected, or what client would make them"
#echo "a preference."
#suites2 ECDHE-RSA-DES-CBC3-SHA

${OPENSSL} ciphers -v "${SUITES}" | grep -v -E "${GREP}" | sort


echo ""
echo "Google uses the same set, plus RC4-MD5 (why?)"
echo ""
