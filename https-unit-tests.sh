#!/bin/bash

function self-signed-certificates-in-chain {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -connect $HOSTPORT 2> /dev/null | grep -i -q 'self signed certificate in certificate chain'

    # grep $? is
    #     0     One or more lines were selected.
    #     1     No lines were selected.
    #     >1    An error occurred.

    if [ "$?" -eq "0" ]; then
        ACTUAL="on"
    else
        ACTUAL="off"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}

function minimum-certificate-chain-length {
    EXPECTED=$1

    numcerts=`echo $URLPATH | openssl s_client -showcerts -connect $HOSTPORT 2> /dev/null | grep 'BEGIN CERTIFICATE' | wc -l | tr -d ' '`

    if [ "$numcerts" -lt "$EXPECTED" ]; then
        # only 1 cert in chain?
        #  probably wrong unless you are yahoo.com
        echo "FAIL: $FUNCNAME $numcerts >= $EXPECTED"
        return 1;
    else
        # at least two certs means we have a chain.  Good.
        echo "PASS: $FUNCNAME $numcerts >=  $EXPECTED"
        return 0
    fi
}

function secure-renegotiation {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -connect $HOSTPORT 2> /dev/null | grep -i -q 'Secure Renegotiation IS supported'

    # grep $? is
    #     0     One or more lines were selected.
    #     1     No lines were selected.
    #     >1    An error occurred.

    if [ "$?" -eq "0" ]; then
        ACTUAL="on"
    else
        ACTUAL="off"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}


function compression {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -connect $HOSTPORT 2> /dev/null | grep -i -q 'Compression: NONE'

    # grep $? is
    #     0     One or more lines were selected.
    #     1     No lines were selected.
    #     >1    An error occurred.

    if [ "$?" -eq "0" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}

function protocol-tls-v12 {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -tls1_2 -connect $HOSTPORT 2> /dev/null > /dev/null

    if [ "$?" -eq "1" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}

function protocol-tls-v11 {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -tls1 -connect $HOSTPORT 2> /dev/null > /dev/null

    if [ "$?" -eq "1" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}

function protocol-tls-v10 {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -tls1 -connect $HOSTPORT 2> /dev/null > /dev/null

    if [ "$?" -eq "1" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}

function protocol-ssl-v3 {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -ssl3 -connect $HOSTPORT 2> /dev/null > /dev/null

    if [ "$?" -eq "1" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}

function protocol-ssl-v2 {
    EXPECTED=$1

    echo $URLPATH | openssl s_client -ssl2 -connect $HOSTPORT 2> /dev/null > /dev/null

    if [ "$?" -eq "1" ]; then
        ACTUAL="off"
    else
        ACTUAL="on"
    fi

    if [ "$EXPECTED" == "$ACTUAL" ]; then
        echo "PASS: $FUNCNAME is $ACTUAL"
        return 0
    else
        echo "FAIL: $FUNCNAME is $ACTUAL"
        return 1
    fi
}


function weak-cipher-suites {
    EXPECTED=$1

    WEAK="off"

    for CIPHER in \
        EXP-RC4-MD5 \
        EXP-RC2-CBC-MD5 \
        EXP-DES-CBC-SHA \
        EXP-EDH-DSS-DES-CBC-SHA \
        EXP-EDH-RSA-DES-CBC-SHA \
        DES-CBC-SHA \
        EDH-DSS-DES-CBC-SHA \
        EDH-RSA-DES-CBC-SHA \
        ; do
        echo $URLPATH | openssl s_client -cipher ${CIPHER} -quiet -connect $HOSTPORT 2> /dev/null > /dev/null
        if [ "$?" -eq "0" ]; then
            ACTUAL="on"
            WEAK="on"
        else
            ACTUAL="off"
        fi
        if [ "$EXPECTED" == "$ACTUAL" ]; then
            RESULT="PASS"
        else
            RESULT="FAIL"
        fi
        echo "$RESULT: $FUNCNAME $CIPHER is $ACTUAL"
    done
    if [ "$WEAK" == "on" ]; then
        return 0
    else
        return 1
    fi

}


function has-cipher-suites {
    EXPECTED=$1
    FNAME=$2
    SUITES=$3
    ANY=0
    for CIPHER in ${SUITES[*]}; do
        echo $URLPATH | openssl s_client -cipher ${CIPHER} -quiet -connect $HOSTPORT 2> /dev/null > /dev/null
        if [ "$?" -eq "0" ]; then
            ACTUAL="on"
            ANY=1
        else
            ACTUAL="off"
        fi
        if [ "$EXPECTED" == "$ACTUAL" ]; then
            RESULT="PASS"
        else
            RESULT="FAIL"
        fi
        echo "$RESULT: $FNAME $CIPHER is $ACTUAL"
    done
    return $ANY
}

function weak-cipher-suites {

    EXPECTED=$1
    FNAME=$FUNCNAME
    SUITES=(\
        EXP-RC4-MD5 \
        EXP-RC2-CBC-MD5 \
        EXP-DES-CBC-SHA \
        EXP-EDH-DSS-DES-CBC-SHA \
        EXP-EDH-RSA-DES-CBC-SHA \
        DES-CBC-SHA \
        EDH-DSS-DES-CBC-SHA \
        EDH-RSA-DES-CBC-SHA \
        )

    has-cipher-suites $EXPECTED $FNAME $SUITES
}


function triple-des-cipher-suites {

    EXPECTED=$1
    FNAME=$FUNCNAME
    SUITES=(\
        ECDHE-RSA-DES-CBC3-SHA \
        ECDHE-ECDSA-DES-CBC3-SHA \
        SRP-DSS-3DES-EDE-CBC-SHA \
        SRP-RSA-3DES-EDE-CBC-SHA \
        EDH-RSA-DES-CBC3-SHA \
        EDH-DSS-DES-CBC3-SHA \
        AECDH-DES-CBC3-SHA \
        SRP-3DES-EDE-CBC-SHA \
        ECDH-RSA-DES-CBC3-SHA \
        ECDH-ECDSA-DES-CBC3-SHA \
        DES-CBC3-SHA \
        DES-CBC3-MD5 \
        PSK-3DES-EDE-CBC-SHA \
        )

    has-cipher-suites $EXPECTED $FNAME $SUITES
}



function recommendation-ssllabs {
    secure-renegotiation on
    protocol-ssl-v2     off

    # neutral
    # protocol-ssl-v3      on

    protocol-tls-v10     on
    protocol-tls-v11     on
    protocol-tls-v12     on

    weak-cipher-suites  off
    compression         off
}
