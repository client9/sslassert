#!/bin/sh

#
# defaults
#
if [ "$OPENSSL" = "" ]; then
    export OPENSSL="openssl"
fi

if [ "$URLPATH" = "" ]; then
    export URLPATH=/
fi

if [[ "$HOSTPORT" != *:* ]]; then
    export HOSTPORT="${HOSTPORT}:443"
fi

export SSLFACTS=""
export SSLASSERT_EXIT=0


function sslfact_add {
    FACT=$1
    if [ "$SSLASSERT_DEBUG" != "" ]; then
        echo $FACT 2>&1
    fi
    SSLFACTS="${SSLFACTS}
${FACT}"
}

function sslfact_certificate_length {
    bits=`echo $URLPATH | ${OPENSSL} s_client -connect $HOSTPORT 2> /dev/null | grep -E 'Server public key is ([0-9]+) bit' |  awk '{ print $5 }'`
    sslfact_add "certificate-length: $bits"
}

function sslfact_smoke_test {
    output=`echo $URLPATH | ${OPENSSL} s_client -connect $HOSTPORT 2>&1`
    if [ "$?" -eq "0" ]; then
        ACTUAL='on'
        sslfact_add "smoke-test: $ACTUAL"
    else
        echo "smoke-test: off"
        echo "${output}"
        SSLASSERT_EXIT=1;
        return 1
    fi
}

function sslfact_self_signed_certificates_in_chain {
    echo $URLPATH | ${OPENSSL} s_client -connect $HOSTPORT 2> /dev/null | grep -i -q 'self signed certificate in certificate chain'
    if [ "$?" -eq "0" ]; then
        ACTUAL="on"
    else
        ACTUAL="off"
    fi
    sslfact_add "self-signed-certificates-in-chain: $ACTUAL"
}

function sslfact_certificate_chain_length {
    numcerts=`echo $URLPATH | ${OPENSSL} s_client -showcerts -connect $HOSTPORT 2> /dev/null | grep 'BEGIN CERTIFICATE' | wc -l | tr -d ' '`
    sslfact_add "certificate-chain-length: $numcerts"
}

function sslfact_secure_renegotiation {
    echo $URLPATH | ${OPENSSL} s_client -connect $HOSTPORT 2> /dev/null | grep -i -q 'Secure Renegotiation IS supported'
    # grep $? is
    #     0     One or more lines were selected.
    #     1     No lines were selected.
    #     >1    An error occurred.

    if [ "$?" -eq "0" ]; then
        ACTUAL="on"
    else
        ACTUAL="off"
    fi
    sslfact_add "secure-renegotiation: ${ACTUAL}"
}


function sslfact_compression {
    EXPECTED=$1

    echo $URLPATH | ${OPENSSL} s_client -connect $HOSTPORT 2> /dev/null | grep -i -q 'Compression: NONE'

    # grep $? is
    #     0     One or more lines were selected.
    #     1     No lines were selected.
    #     >1    An error occurred.

    if [ "$?" -eq "0" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "compression: ${ACTUAL}"
}

function sslfact_protocol_tls_v12 {
    cipher=`echo $URLPATH | ${OPENSSL} s_client -tls1_2 -connect $HOSTPORT 2> /dev/null | awk -F ': *' '/Cipher.*:/ { print $2 }'`
    if [ "$cipher" = "0000" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "protocol-tls-v12: ${ACTUAL}"
    sslfact_add "protocol-tls-v12-default: ${cipher}"

    if [ "$ACTUAL" = "on" ] ; then
        sslfact_cipher_suites_tls12_common
        sslfact_cipher_suites_tls12_strange
    fi
}

function sslfact_protocol_tls_v11 {
    cipher=`echo $URLPATH | ${OPENSSL} s_client -tls1_1 -connect $HOSTPORT 2> /dev/null | awk -F ': *' '/Cipher.*:/ { print $2 }'`
    if [ "$cipher" = "0000" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "protocol-tls-v11: ${ACTUAL}"
    sslfact_add "protocol-tls-v11-default: ${cipher}"
}

function sslfact_protocol_tls_v10 {
    cipher=`echo $URLPATH | ${OPENSSL} s_client -tls1 -connect $HOSTPORT 2> /dev/null | awk -F ': *' '/Cipher.*:/ { print $2 }'`
    if [ "$cipher" = "0000" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "protocol-tls-v10: ${ACTUAL}"
    sslfact_add "protocol-tls-v10-default: ${cipher}"
}

function sslfact_protocol_ssl_v3 {
    cipher=`echo $URLPATH | ${OPENSSL} s_client -ssl3 -connect $HOSTPORT 2> /dev/null | awk -F ': *' '/Cipher.*:/ { print $2 }'`
    if [ "$cipher" = "0000" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "protocol-ssl-v3: ${ACTUAL}"
    sslfact_add "protocol-ssl-v3-default: ${cipher}"
}

function sslfact_protocol_ssl_v2 {
    cipher=`echo $URLPATH | ${OPENSSL} s_client -ssl2 -connect $HOSTPORT 2> /dev/null | awk -F ': *' '/Cipher.*:/ { print $2 }'`
    if [ "$cipher" = "0000" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "protocol-ssl-v2: ${ACTUAL}"
    sslfact_add "protocol-ssl-v2-default: ${cipher}"
}

# re: https://community.qualys.com/blogs/securitylabs/2011/10/17/mitigating-the-beast-attack-on-tls
# Update (20 Jan 2012): In testing OpenSSL 1.0.1-beta2, which came out
# yesterday, I realised that it will happily negotiate AES-CBC-SHA256
# even on a TLSv1.0 connection. So I removed it from the
# recommendation, replacing it with two other TLSv1.2 cipher suites.
#
# It appears more modern releases do not have this bug
#
# This should be OFF
#
function sslfact_tls12_suite_allowed_on_tls10 {
    cipher=`echo $URLPATH | ${OPENSSL} s_client -tls1 -cipher AES128-SHA256 -connect $HOSTPORT 2> /dev/null | awk -F ': *' '/Cipher.*:/ { print $2 }'`
    if [ "$cipher" = "0000" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "protocol-tls12-suite-allowed-on-tls10: ${ACTUAL}"
}


function sslfact_cipher_suites_all {
    OPENSSLSUITES=`${OPENSSL} ciphers -v ALL:COMPLEMENTOFALL | awk '{ print $1 }' | sort -u`
    sslfact_cipher_suites $OPENSSLSUITES
}

function sslfact_cipher_suites_tls12_strange {
    SUITES="`${OPENSSL} ciphers -v ALL | grep 1.2 | grep -E 'ECDSA|ADH|ECDH-' | awk '{ print $1 }' | sort -u`"
    TAGS="`echo ${SUITES} | tr \"\\n\" ':'`"
    echo $URLPATH | ${OPENSSL} s_client -cipher '${TAGS}' -connect $HOSTPORT 2> /dev/null > /dev/null
    if [ "$?" -eq "0" ]; then
        sslfact_cipher_suites $SUITES
    fi
}

function sslfact_cipher_suites_tls12_common {
    SUITES="`${OPENSSL} ciphers -v ALL | grep 1.2 | grep -v -E 'ECDSA|ADH|ECDH-' | awk '{ print $1 }' | sort -u`"
    sslfact_cipher_suites $SUITES
}

function sslfact_cipher_suites_sslv3_strange {
    # get seldom used ciphers
    TAGS='DSS:SRP:PSK:NULL:ADH:AECDH:ECDSA'
    echo $URLPATH | ${OPENSSL} s_client -cipher '${TAGS}' -connect $HOSTPORT 2> /dev/null > /dev/null
    if [ "$?" -eq "0" ]; then
        SUITES=`${OPENSSL} ciphers -v '${TAGS}' | grep -v 1.2 | awk '{ print $1 }' | sort -u`
        sslfact_cipher_suites $SUITES
    fi
}

function sslfact_cipher_suites_sslv3_common {
    # get seldom used ciphers
    COMMON="`${OPENSSL} ciphers -v 'ALL:!DSS:!SRP:!PSK:!NULL:!ADH:!AECDH:!ECDSA' | grep -v 1.2 | awk '{ print $1 }' | sort -u`"
    sslfact_cipher_suites $COMMON
}

function sslfact_cipher_suites {
    while (( "$#" )); do
        CIPHER=$1
        echo $URLPATH | ${OPENSSL} s_client -cipher ${CIPHER} -connect $HOSTPORT 2> /dev/null > /dev/null
        if [ "$?" -eq "0" ]; then
            sslfact_add "cipher-suite-${CIPHER}: on"
#        else
#            sslfact_add "cipher-suite-${CIPHER}: off"
        fi
        shift
    done
}

function has_cipher_suites {
    FNAME=$1
    COUNT=$2
    if [ "$COUNT" == "0" ]; then
       ACTUAL="off"
    else
       ACTUAL="on"
    fi
    sslfact_add "${FNAME}: ${ACTUAL}"
}

function sslfact_crypto_weak {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c -E 'EXP-|-DES-CBC-'`
    has_cipher_suites "crypto-weak" $COUNT
}

function sslfact_crypto_null {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c 'NULL-'`
    has_cipher_suites "crypto-null" $COUNT
}

function sslfact_crypto_adh {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c 'ADH-'`
    has_cipher_suites "crypto-adh" $COUNT
}

function sslfact_crypto_aes {
    # plain aes, no ecdhe- or dh-... aes
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep 'AES' | grep -c -v 'DHE`
    has_cipher_suites "crypto-aes" $COUNT
}

function sslfact_crypto_gcm {
    # plain aes, no ecdhe- or dh-... aes
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c 'GCM'`
    has_cipher_suites "crypto-gcm" $COUNT
}

function sslfact_crypto_idea {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite.*: on' | grep -c IDEA-`
    has_cipher_suites "crypto-idea" $COUNT
}

function sslfact_crypto_rc4 {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c RC4`
    has_cipher_suites "crypto-rc4" $COUNT
}

function sslfact_crypto_tripledes {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c -E '3DES|CBC3'`
    has_cipher_suites "crypto-3des" $COUNT
}

function sslfact_crypto_camellia {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c CAMELLIA`
    has_cipher_suites "crypto-camellia" $COUNT
}

function sslfact_crypto_md5 {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c MD5`
    has_cipher_suites 'crypto-md5' $COUNT
}

function sslfact_crypto_sha160 {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep SHA | grep -c -v -E 'SHA256|SHA384|SHA512'`
    has_cipher_suites 'crypto-sha160' $COUNT
}

function sslfact_crypto_seed {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c SEED`
    has_cipher_suites 'crypto-seed' $COUNT
}

function sslfact_crypto_suite_count {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | wc -l | tr -d ' '`
    sslfact_add "crypto-suite-count: ${COUNT}"
}

function sslfact_crypto_forward_secrecy {
    # ignoring insecure DES based suites
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -E 'ECDHE|EDH-' | grep -c -v 'DES-CBC-'`
    has_cipher_suites 'crypto-forward-secrecy' $COUNT
}

function sslfact_crypto_ecdhe {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c  ECDHE`
    has_cipher_suites 'crypto-ecdhe' $COUNT
}

function sslfact_crypto_dhe {
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -v ECDHE | grep -c DHE`
    has_cipher_suites 'crypto-dhe' $COUNT
}

function sslfact_crypto_winxp {
    # technically RC4-SHA and RC4-MD5 are ok for Windows XP and IE <=8 too
    # however, WinXP can be put in FIPS compliance mode, which will eliminate
    # RC4-SHA, RC4-MD5.  This only leaves DES-CBC3-SHA  :-(
    COUNT=`echo "$SSLFACTS" | grep -i 'cipher-suite-.*: on' | grep -c DES-CBC3-SHA`
    has_cipher_suites 'crypto-winxp-ie-compatible' $COUNT
}

function sslfact_beast_attack {
    BEAST=0
    echo "$SSLFACTS" | grep -i -q -E 'protocol-tls-v10-default:.*(RC4|0000)'
    if [ "$?" -eq 0 ]; then
        let BEAST+=1
    fi
    echo "$SSLFACTS" | grep -i -q -E 'protocol-ssl-v3-default:.*(RC4|0000)'
    if [ "$?" -eq 0 ]; then
        let BEAST+=1
    fi
    if [ "$BEAST" -eq 2 ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi
    sslfact_add "beast-attack: ${ACTUAL}"
}

function sslassert {
    read -r KEY OP EXPECTED <<< $1

    # take only first value
    ACTUAL=`echo "$SSLFACTS" | grep -i "$KEY" | head -1 | awk -F : '{ print \$2 }' | tr -d ' '`

    if [ "$?" -ne 0 ]; then
        echo "ERR : ${KEY}: not found!!"
        return 2
    fi

    if [ "$ACTUAL" "$OP" "$EXPECTED" ]; then
        echo "PASS: ${KEY}: ${ACTUAL} ${OP} ${EXPECTED}"
        return 0
    fi

    echo "FAIL: ${KEY}: ${ACTUAL} ${OP} ${EXPECTED}"
    SSLASSERT_EXIT=1
    return 1
}

function sslassert_init {
    sslfact_smoke_test
    if [ "$?" -eq "1" ]; then
        return $SSLASSERT_EXIT
    fi
    sslfact_protocol_tls_v12
    sslfact_protocol_tls_v11
    sslfact_protocol_tls_v10
    sslfact_protocol_ssl_v3
    sslfact_protocol_ssl_v2
    sslfact_cipher_suites_sslv3_common
    sslfact_cipher_suites_sslv3_strange

    sslfact_crypto_weak
    sslfact_crypto_null
    sslfact_crypto_adh
    sslfact_crypto_md5
    sslfact_crypto_rc4
    sslfact_crypto_gcm
    sslfact_crypto_idea
    sslfact_crypto_seed
    sslfact_crypto_dhe
    sslfact_crypto_ecdhe
    sslfact_crypto_camellia
    sslfact_crypto_tripledes
    sslfact_crypto_forward_secrecy
    sslfact_crypto_sha160
    sslfact_crypto_winxp
    sslfact_crypto_suite_count
    sslfact_certificate_length
    sslfact_self_signed_certificates_in_chain
    sslfact_certificate_chain_length
    sslfact_secure_renegotiation
    sslfact_compression
    sslfact_tls12_suite_allowed_on_tls10
    sslfact_beast_attack
}
sslassert_init

