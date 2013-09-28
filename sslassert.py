#!/usr/bin/env python

"""
Fast fact generation and assertions for SSL/TLS (https) servers
https://github.com/client9/sslassert
"""

import base64

import subprocess
import logging
import datetime
import time

import ct.crypto.cert

#from OpenSSL import crypto
#from pyasn1_modules import rfc2459
#from Crypto.Util import asn1
#import pyasn1.error
#from pyasn1.type import univ, tag
#from pyasn1.codec.der import decoder as der_decoder

#oids = {
#'1.3.6.1.5.5.7.3.1': 'id-kp-serverAuth ',
#'1.3.6.1.5.5.7.3.2': 'id-kp-clientAuth',
#'1.3.6.1.5.5.7.48.1': 'OCSP',
#'1.3.6.1.5.5.7.48.2': 'id-ad-caIssuers',
#}

class sslassert(object):

    SSLV3_UNCOMMON = (
        'ADH-AES128-SHA',
        'ADH-AES256-SHA',
        'ADH-CAMELLIA128-SHA',
        'ADH-CAMELLIA256-SHA',
        'ADH-DES-CBC-SHA',
        'ADH-DES-CBC3-SHA',
        'ADH-RC4-MD5',
        'ADH-SEED-SHA',
        'AECDH-AES128-SHA',
        'AECDH-AES256-SHA',
        'AECDH-DES-CBC3-SHA',
        'AECDH-NULL-SHA',
        'AECDH-RC4-SHA',
        'ECDH-ECDSA-AES128-SHA',
        'ECDH-ECDSA-AES256-SHA',
        'ECDH-ECDSA-DES-CBC3-SHA',
        'ECDH-ECDSA-NULL-SHA',
        'ECDH-ECDSA-RC4-SHA',
        'ECDH-RSA-AES128-SHA',
        'ECDH-RSA-AES256-SHA',
        'ECDH-RSA-DES-CBC3-SHA',
        'ECDH-RSA-NULL-SHA',
        'ECDH-RSA-RC4-SHA',
        'ECDHE-ECDSA-NULL-SHA',
        'ECDHE-RSA-NULL-SHA',
        'EDH-DSS-DES-CBC-SHA',
        'EXP-ADH-DES-CBC-SHA',
        'EXP-ADH-RC4-MD5',
        'EXP-EDH-DSS-DES-CBC-SHA',
        'EXP-EDH-RSA-DES-CBC-SHA',
        'IDEA-CBC-MD5',
        'IDEA-CBC-SHA',
        'NULL-MD5',
        'NULL-SHA',
        'PSK-3DES-EDE-CBC-SHA',
        'PSK-AES128-CBC-SHA',
        'PSK-AES256-CBC-SHA',
        'PSK-RC4-SHA',
        'EDH-DSS-DES-CBC3-SHA',
        'EDH-RSA-DES-CBC-SHA',
        'EDH-RSA-DES-CBC3-SHA',
        'SEED-SHA',
        'SRP-3DES-EDE-CBC-SHA',
        'SRP-AES-128-CBC-SHA',
        'SRP-AES-256-CBC-SHA',
        'SRP-DSS-3DES-EDE-CBC-SHA',
        'SRP-DSS-AES-128-CBC-SHA',
        'SRP-DSS-AES-256-CBC-SHA',
        'SRP-RSA-3DES-EDE-CBC-SHA',
        'SRP-RSA-AES-128-CBC-SHA',
        'SRP-RSA-AES-256-CBC-SHA',
        'DHE-DSS-CAMELLIA128-SHA',
        'DHE-DSS-CAMELLIA256-SHA',
        'DHE-RSA-CAMELLIA128-SHA',
        'DHE-RSA-CAMELLIA256-SHA',
        'ECDHE-ECDSA-AES128-SHA',
        'ECDHE-ECDSA-AES256-SHA',
        'ECDHE-ECDSA-DES-CBC3-SHA',
        'ECDHE-ECDSA-RC4-SHA',
        'DHE-DSS-AES128-SHA',
        'DHE-DSS-AES256-SHA',
        'DHE-DSS-SEED-SHA',
    )

    SSLV3_COMMON = (
        'AES128-SHA',
        'AES256-SHA',
        'CAMELLIA128-SHA',
        'CAMELLIA256-SHA',
        'DES-CBC-MD5',
        'DES-CBC-SHA',
        'DES-CBC3-MD5',
        'DES-CBC3-SHA',
        'DHE-RSA-AES128-SHA',
        'DHE-RSA-AES256-SHA',
        'DHE-RSA-SEED-SHA',
        'ECDHE-RSA-AES128-SHA',
        'ECDHE-RSA-AES256-SHA',
        'ECDHE-RSA-DES-CBC3-SHA',
        'ECDHE-RSA-RC4-SHA',
        'EXP-DES-CBC-SHA',
        'EXP-RC2-CBC-MD5',
        'EXP-RC4-MD5',
        'RC2-CBC-MD5',
        'RC4-MD5',
        'RC4-SHA',
    )

    TLS12_COMMON = (
        'AES128-GCM-SHA256',
        'AES128-SHA256',
        'AES256-GCM-SHA384',
        'AES256-SHA256',
        'DHE-RSA-AES128-GCM-SHA256',
        'DHE-RSA-AES128-SHA256',
        'DHE-RSA-AES256-GCM-SHA384',
        'DHE-RSA-AES256-SHA256',
        'ECDHE-RSA-AES128-GCM-SHA256',
        'ECDHE-RSA-AES128-SHA256',
        'ECDHE-RSA-AES256-GCM-SHA384',
        'ECDHE-RSA-AES256-SHA384'
    )
    TLS12_UNCOMMON = (
        'ADH-AES128-GCM-SHA256',
        'ADH-AES128-SHA256',
        'ADH-AES256-GCM-SHA384',
        'ADH-AES256-SHA256',
        'DHE-DSS-AES128-GCM-SHA256',
        'DHE-DSS-AES128-SHA256',
        'DHE-DSS-AES256-GCM-SHA384',
        'DHE-DSS-AES256-SHA256',
        'ECDH-ECDSA-AES128-GCM-SHA256',
        'ECDH-ECDSA-AES128-SHA256',
        'ECDH-ECDSA-AES256-GCM-SHA384',
        'ECDH-ECDSA-AES256-SHA384',
        'ECDH-RSA-AES128-GCM-SHA256',
        'ECDH-RSA-AES128-SHA256',
        'ECDH-RSA-AES256-GCM-SHA384'
        'ECDH-RSA-AES256-SHA384',
        'ECDHE-ECDSA-AES128-GCM-SHA256',
        'ECDHE-ECDSA-AES128-SHA256',
        'ECDHE-ECDSA-AES256-GCM-SHA384',
        'ECDHE-ECDSA-AES256-SHA384'
    )

    def __init__(self, opensslexe=None):
        self.facts = {}
        self.path = '/'
        self.hostport = 'localhost'
        if ':' not in self.hostport:
            self.hostport += ':443'
        if opensslexe is None:
            self.openssl = ['openssl',]
        else:
            self.openssl = opensslexe

    def connect(self, *args):
        cmd = self.openssl[:]
        cmd.append('s_client')
        cmd += args
        cmd.append('-connect')
        cmd.append(self.hostport)
        #print ' '.join(cmd)
        sock = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr =  sock.communicate(self.path)
        return sock.returncode, stdout, stderr

    def doit(self, args, input=None):
        cmd = self.openssl[:]
        cmd += args
        sock = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sock.communicate(input)
        return sock.returncode, stdout, stderr

    def get_suites(self, tag):
        (stdout,stderr) = self.doit(['ciphers', tag])
        return stdout.split(':')

    def add_fact(self, key, value):
        #logging.debug("{0} = {1}".format(key.lower(),value))
        print "{0} = {1}".format(key.lower(),value)
        self.facts[key.lower()] = value

    def get_fact(self, key, default=None):
        return self.facts.get(key.lower(), default)

    def smoke(self):
        self.add_fact('ssl_openssl_command', ' '.join(self.openssl))
        (code, stdout,stderr) = self.doit(['version'])
        vstr = stdout.strip()
        self.add_fact('ssl_openssl_version_string', vstr)
        parts = vstr.split()[1].split('.')
        self.add_fact('ssl_openssl_version_major', int(parts[0]))
        self.add_fact('ssl_openssl_version_minor', int(parts[1]))

        (code, stdout,stderr) = self.doit(['ciphers', 'ALL:COMPLEMENTOFALL'])
        suites = stdout.split(':')
        self.add_fact('ssl_openssl_supported-suites', len(suites))

        ecc = False
        rc4 = False
        tls12 = False
        for suite in suites:
            if 'ECDHE-' in suite or 'ECDH-' in suite:
                ecc = True
            if 'AES256-SHA256' in suite:
                tls12 = True
            if 'RC4' in suite:
                rc4 = True
        self.add_fact('ssl_openssl_elliptic-curve', ecc)
        self.add_fact('ssl_openssl_rc4-cipher', rc4)
        self.add_fact('ssl_openssl_tlsv1.2', tls12)
        self.add_fact('ssl_openssl_target', 'https://' + self.hostport + self.path)

        (code, stdout, stderr) = self.connect()
        if code != 0:
            self.add_fact('ssl_openssl_connect', stderr.split("\n")[0].strip())
            return 1
        else:
            self.add_fact('ssl_openssl_connect', True)

        signed = 'self signed certificate in certificate chain' in stdout
        self.add_fact('ssl_certificate_chain-self-signed', signed)

        lines = stdout.split("\n")
        count = 0
        do_count = False
        for line in lines:
            if line == 'Certificate chain':
                do_count = True
            elif do_count and " s:" in line:
                count += 1
            elif do_count and line == '---':
                break

        self.add_fact('ssl_certificate_chain-length', count)

        for line in lines:
            if 'Server public key is' in line:
                self.add_fact('ssl_certificate_length', line.split(' ')[4])
                break



        certtxt = stdout

        lines = certtxt.split('\n')
        substrate = ''
        state = 0
        for line in lines:
            if line == '-----BEGIN CERTIFICATE-----':
                state = 1
            elif line == '-----END CERTIFICATE-----':
                break
            elif state == 1:
                substrate = substrate + base64.b64decode(line)


        cert = ct.crypto.cert.Certificate(substrate)
        self.add_fact('ssl_certificate_subject-common-name', cert.subject_common_name())
        self.add_fact('ssl_certificate_subject-name', cert.subject_name())
        self.add_fact('ssl_certificate_issuer-name', cert.issuer_name())
        self.add_fact('ssl_certificate_version', cert.version())

        val = time.mktime(cert.not_before())
        days = (time.time() - val) / 86400.0
        self.add_fact('ssl_certificate_not-before', int(val))
        self.add_fact('ssl_certificate_days-since-start', int(days))

        val = time.mktime(cert.not_after())
        days = (val - time.time()) / 86400.0
        self.add_fact('ssl_certificate_not-after', int(val))
        self.add_fact('ssl_certificate_days-until-end', int(days))
        self.add_fact('ssl_certificate_serial-number', str(cert.serial_number()))

        san = cert.subject_alternative_names()
        val = [ part.value() for part in san ]
        self.add_fact('ssl_certificate_subject-alternative-name', ','.join(val))

        junk = cert.authority_info_access()
        for oid_val, url_val in junk:
            self.add_fact('ssl_certificate_authorityinfoaccess_' + oid_val.short_name().lower(), url_val.value())

        #cert = crypto.load_certificate(crypto.FILETYPE_PEM, certtxt)

        #self.add_fact('ssl_certificate_serial-number', cert.get_serial_number())
        #self.add_fact('ssl_certificate_version', cert.get_version())

        #self.add_fact('ssl_certificate_extentions-count', cert.get_extension_count())
        if False:
            #for i in range(cert.get_extension_count()):
            ext = cert.get_extension(i)
            shortname = ext.get_short_name().lower()
            rawdata = ext.get_data()
            if shortname == 'subjectaltname':
                parts = der_decoder.decode(rawdata, asn1Spec=rfc2459.SubjectAltName())[0]
                domains = []
                for part in parts:
                    domains.append( str(part.getComponentByPosition(2)))
                data = ','.join(domains)
            elif shortname == 'authoritykeyidentifier':
                parts = der_decoder.decode(rawdata, asn1Spec=rfc2459.AuthorityKeyIdentifier())
                data = str(parts[0].getComponentByPosition(0)).encode('hex')
            elif shortname == 'keyusage':
                data = der_decoder.decode(rawdata, asn1Spec=rfc2459.KeyUsage())
            elif shortname == 'certificatepolicies':
                data = der_decoder.decode(rawdata, asn1Spec=rfc2459.CertificatePolicies())[0]
            elif shortname == 'subjectkeyidentifier':
                data = der_decoder.decode(rawdata)[0].asOctets().encode('hex')
            elif shortname == 'issueraltname':
                data = der_decoder.decode(rawdata, asn1Spec=rfc2459.IssuerAltName())
                domains = []
                for i in range(len(data[0])):
                    domains.append(str(data[0].getComponentByPosition(i).getComponentByPosition(2)))
                data = ','.join(domains)
            elif shortname == 'authorityinfoaccess':
                data = der_decoder.decode(rawdata, asn1Spec=rfc2459.AuthorityInfoAccessSyntax())[0]
                for part in data:
                    #print oids[str(part[0])], part[1].getComponentByPosition(6)
                    self.add_fact('ssl_certificate_extention_authorityinfoaccess_' + oids[str(part[0])],
                                  part[1].getComponentByPosition(6))
                #continue
            elif shortname == 'basicconstraintsx':
                data = der_decoder.decode(rawdata, asn1Spec=rfc2459.BasicConstraints())
            elif shortname == 'extendedkeyusage':
                parts = der_decoder.decode(rawdata)[0]
                data = ','.join([oids[str(part)] for part in parts])
            elif shortname == 'crldistributionpoints':
                #data= 'FAIL'
                #data = der_decoder.decode(rawdata, asn1Spec=rfc2459.id_ce_cRLDistributionPoints )
                #data = der_decoder.decode(rawdata, asn1Spec=rfc2459.CRLDistPointsSyntax() )
                #data = der_decoder.decode(rawdata, asn1Spec=rfc2459.IssuingDistributionPoint() )
                pass
            else:
                try:
                    data = der_decoder.decode(rawdata)[0]
                except pyasn1.error.PyAsn1Error:
                    data = 'FAIL' + str(rawdata)

            self.add_fact('ssl_certificate_extention_' + shortname, data)

        #(code, stdout, stderr) = self.doit(['x509', '-noout', '-fingerprint'], certtxt)
        #self.add_fact('ssl_certificate_fingerprint', stdout.strip().split('=')[1])

        #(code, stdout, stderr) = self.doit(['x509', '-noout', '-subject'], certtxt)
        #idx = stdout.find('CN=')
        #if idx > 0:
        #    self.add_fact('ssl_certificate_common-name', stdout[idx+3:].strip())

        #(code, stdout, stderr) = self.doit(['x509', '-noout', '-ocsp_uri'], certtxt)
        #parts = stdout.strip()
        #if len(parts) == 0:
        #    parts = None
        #self.add_fact('ssl_certificate_oscp-uri', parts)

        #(code, stdout, stderr) = self.doit(['x509', '-noout', '-ocspid'], certtxt)
        #parts = stdout.strip()
        #if len(parts) == 0:
        #    parts = None
        #self.add_fact('ssl_certificate_oscp-id', parts)

        #(code, stdout, stderr) = self.doit(['x509', '-noout', '-startdate'], certtxt)
        #datestr = stdout.strip().split('=')[1]
        #datenow = datetime.datetime.now()
        #dateexp = datetime.datetime.strptime(datestr, '%b %d %H:%M:%S %Y %Z')
        #self.add_fact('ssl_certificate_days-since-expiration', (datenow - dateexp).days)

        #(code, stdout, stderr) = self.doit(['x509', '-noout', '-enddate'], certtxt)
        #datestr = stdout.strip().split('=')[1]
        #datenow = datetime.datetime.now()
        #dateexp = datetime.datetime.strptime(datestr, '%b %d %H:%M:%S %Y %Z')
        #self.add_fact('ssl_certificate_days-till-expiration', (dateexp-datenow).days)
        return 0

    def protocol_tls12(self):
        (code, stdout, stderr) = self.connect('-tls1_2')
        cipher = self._get_cipher(stdout)
        self.add_fact('ssl_protocol_tls12', cipher)

    def protocol_tls11(self):
        (code, stdout,stderr) = self.connect('-tls1_1')
        cipher = self._get_cipher(stdout)
        self.add_fact('ssl_protocol_tls11', cipher)

    def protocol_tls10(self):
        (code, stdout,stderr) = self.connect('-tls1')
        cipher = self._get_cipher(stdout)
        self.add_fact('ssl_protocol_tls10', cipher)

    def protocol_ssl3(self):
        (code, stdout,stderr) = self.connect('-ssl3')
        cipher = self._get_cipher(stdout)
        self.add_fact('ssl_protocol_ssl3', cipher)

    def protocol_ssl2(self):
        (code, stdout, stderr) = self.connect('-ssl2')
        cipher = self._get_cipher(stdout)
        self.add_fact('ssl_protocol_ssl2', cipher)

    def _get_cipher(self, stdout):
        cipher = None
        for line in stdout.split("\n"):
            if 'Cipher    :' in line:
                cipher = line.split(':')[1].strip()
                if cipher == '0000':
                    cipher = None
                break
        return cipher

    def cipher_preference(self, suites):
        (code,stdout,stderr) = self.connect('-cipher', ':'.join(suites))
        for line in stdout.split("\n"):
            line = line.strip()
            if line.startswith('Cipher'):
                key,value = line.split(':')
                value = value.strip()
                return value
        print "ERROR"
        return 0

    def cipher_order(self):
        #print self.suites
        ordered = []
        suites = self.suites[:]
        while len(suites) > 1:
            pref = self.cipher_preference(suites)
            ordered.append(pref)
            suites.remove(pref)

        ordered.append(suites[0])

        for i,s in enumerate(ordered):
            self.add_fact('ssl_cipher_suite_' + s.lower(), True)
            if i+1 < 10:
                val = '0' + str(i+1)
            else:
                val = str(i+1)
            self.add_fact('ssl_cipher-order_' + val, s.lower())
        self.add_fact('ssl_cipher-count', len(ordered))

    def cipher_algorithm_usage(self):
        tests = [
            [ 'NULL', 'ssl_algorithm_null'],
            [ 'RC2', 'ssl_algoirthm_rc2'],
            [ 'ECDHE-ECDSA-', 'ssl_algorithm_ecdhe-ecdsa'],
            [ '-DSS-', 'ssl_algorithm_dsa'],
            [ 'CAMELLIA', 'ssl_algorithm_camellia'],
            [ 'IDEA', 'ssl_algorithm_idea'],
            [ 'SEED', 'ssl_algorithm_seed'],
            [ 'EXP-', 'ssl_algorithm_export'],
            [ 'DES-CBC-', 'ssl_algorithm_des'],
            [ 'SRP-', 'ssl_algorithm_srp'],
            [ 'AECDH-', 'ssl_algorithm_aecdh'],
            [ 'ADH-', 'ssl_algorithm_adh'],
            [ 'PSK-', 'ssl_algorithm_psk'],
            [ 'ECDH-', 'ssl_algorithm_ecdh'],
            [ 'MD5', 'ssl_algorithm_md5'],
            [ 'RC4', 'ssl_algorithm_rc4'],
        ]

        for t in tests:
            found = None
            for suite in self.suites:
                if t[0] in suite:
                    found = suite
            self.add_fact(t[1], found)

    def cipher_suites(self, suites):
        for suite in suites:
            (code, stdout, stderr) = self.connect('-cipher', suite)
            if code == 0:
                self.suites.append(suite)
            else:
                self.add_fact('ssl_cipher_suite_' + suite, False)

    def cipher_suites_tls12(self):
        if not self.get_fact('ssl_protocol_tls12', False):
            return

        # test common suites, one by one
        self.cipher_suites(sslassert.TLS12_COMMON)

        # bulk-test for unusual ones
        (code, stdout, stderr) = self.connect('-cipher', ':'.join(sslassert.TLS12_UNCOMMON))
        if code == 0:
            # test one by one afterall
            self.cipher_suites(slassert.TLS12_UNCOMMON)

    def cipher_suites_ssl(self):
        # test common suites, one by one
        self.cipher_suites(sslassert.SSLV3_COMMON)

        # bulk-test for unusual ones
        (code, stdout, stderr) = self.connect('-cipher', ':'.join(sslassert.SSLV3_UNCOMMON))
        if code == 0:
            # test one by one afterall
            self.cipher_suites(sslassert.SSLV3_UNCOMMON)

    def check(self, test):
        for line in test.split("\n"):
            line = line.strip()
            if len(line) == 0:
                continue
            args = line.split()
            if len(args) == 4:
                key = args[0].lower()
                op = args[1] + ' ' + args[2]
                expected = args[3]
            else:
                key = args[0].lower()
                op = args[1]
                expected = args[2]

            actual = self.get_fact(key, None)

            if expected.upper() == 'NONE' or expected.upper() == 'NULL':
                expected = None
            if type(actual) == type(True):
                expected =  (expected.upper() == 'TRUE')
            elif type(actual) == type(1) or type(actual) == type(1.0):
                expected = float(expected)

            operators = {
                '=': lambda x,y: x == y,
                '==': lambda x,y: x == y,
                '!=': lambda x,y: x != y,
                '<>': lambda x,y: x != y,
                '<': lambda x,y: x < y,
                '<=': lambda x,y: x <= y,
                '>': lambda x,y: x > y,
                '>=': lambda x,y: x >= y,
                'is': lambda x,y: x is y,
                'is not': lambda x,y: x is not y,
                'in': lambda x,y: x in y,
                'not in': lambda x,y: x not in y
            }
            fn = operators[op]
            #print type(actual), type(expected)
            result = fn(actual, expected)
            print "{4} {0} = {1} {2} {3}".format(key, actual, op, expected, result and "PASS" or "FAIL")

    def test(self, host, path='/'):
        self.suites = []
        self.facts = {}
        if ':' not in host:
            host += ':443'
        self.hostport = host
        self.path = path

        if self.smoke() == 1:
            return self.facts
        self.protocol_tls12()
        self.protocol_tls11()
        self.protocol_tls10()
        self.protocol_ssl3()
        self.protocol_ssl2()
        self.cipher_suites_tls12()
        self.cipher_suites_ssl()
        self.cipher_order()
        self.cipher_algorithm_usage()

        return self.facts

def sslassert_test(target, tests, openssl=None):
    sf = sslassert(target, openssl=openssl)
    sf.check(tests)


if __name__ == '__main__':
    import sys
    target = sys.argv[1]
    if ':' not in target:
        target += ':443'

    import json
    sf = sslassert(['timeout', '10', 'openssl'])
    sf.test(target)

    sys.exit(0)
    print '----'
    sf.check("""
openssl-version-major >= 1
openssl-elliptic-curve is True
openssl-rc4-cipher is True

certificate-chain-self-signed is False
certificate-common-name == libinjection.client9.com
certificate-chain-length > 1
certificate-days-till-expiration > 30

protocol-tls12 is not None
protocol-tls11 is not None
protocol-tls10 is not None
protocol-ssl3 is not None
protocol-ssl2 is None

cipher-suite-ecdhe-rsa-aes128-gcm-sha256 = True
cipher-suite-ecdhe-rsa-aes256-gcm-sha384 = True
cipher-suite-dhe-rsa-aes128-gcm-sha256 = True
cipher-suite-dhe-rsa-aes256-gcm-sha384 = True
cipher-suite-ecdhe-rsa-aes128-sha256 = True
cipher-suite-ecdhe-rsa-aes256-sha384 = True
cipher-suite-dhe-rsa-aes128-sha256 = True
cipher-suite-dhe-rsa-aes256-sha256 = True
cipher-suite-ecdhe-rsa-rc4-sha = True
cipher-suite-ecdhe-rsa-aes128-sha = True
cipher-suite-ecdhe-rsa-aes256-sha = True
cipher-suite-dhe-rsa-aes128-sha = True
cipher-suite-dhe-rsa-aes256-sha = True
cipher-suite-ecdhe-rsa-des-cbc3-sha = True
cipher-suite-aes128-gcm-sha256 = True
cipher-suite-aes256-gcm-sha384 = True
cipher-suite-aes128-sha256 = True
cipher-suite-aes256-sha256 = True
cipher-suite-rc4-sha = True
cipher-suite-aes128-sha = True
cipher-suite-aes256-sha = True
cipher-suite-des-cbc3-sha = True
""")


