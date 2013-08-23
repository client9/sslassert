#!/usr/bin/env python
import subprocess
import datetime

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
        'DHE-DSS-AES128-GCM-SHA256',
        'DHE-DSS-AES128-SHA256',
        'DHE-DSS-AES256-GCM-SHA384',
        'DHE-DSS-AES256-SHA256',
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

    def __init__(self, hostport, path='/', openssl=None):
        self.facts = {}
        self.path = path
        self.hostport = hostport
        if ':' not in self.hostport:
            self.hostport += ':443'
        if openssl is None:
            self.openssl = ['openssl',]
        else:
            self.openssl = openssl

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
        print "{0} = {1}".format(key.lower(),value)
        self.facts[key.lower()] = value

    def get_fact(self, key, default=None):
        return self.facts.get(key.lower(), default)

    def smoke(self):
        self.add_fact('openssl-command', ' '.join(self.openssl))
        (code, stdout,stderr) = self.doit(['version'])
        vstr = stdout.strip()
        self.add_fact('openssl-version', vstr)
        parts = vstr.split()[1].split('.')
        self.add_fact('openssl-version-major', int(parts[0]))
        self.add_fact('openssl-version-minor', int(parts[1]))

        (code, stdout,stderr) = self.doit(['ciphers', 'ALL:COMPLEMENTOFALL'])
        suites = stdout.split(':')
        self.add_fact('openssl-supported-suites', len(suites))

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
        self.add_fact('openssl-elliptic-curve', ecc)
        self.add_fact('openssl-rc4-cipher', rc4)
        self.add_fact('openssl-TLSv1.2', tls12)

    def certificate(self):
        (code, stdout, stderr) = self.connect()
        if code != 0:
            self.add_fact('openssl-connect', stderr)
            return 1
        else:
            self.add_fact('openssl-connect', True)

        signed = 'self signed certificate in certificate chain' in stdout
        self.add_fact('certificate-chain-self-signed', signed)

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

        self.add_fact('certificate-chain-length', count)

        for line in lines:
            if 'Server public key is' in line:
                self.add_fact('certificate-length', line.split(' ')[4])
                break

        cert = stdout

        (code, stdout, stderr) = self.doit(['x509', '-noout', '-fingerprint'], cert)
        self.add_fact('certificate-fingerprint', stdout.strip().split('=')[1])
        (code, stdout, stderr) = self.doit(['x509', '-noout', '-subject'], cert)
        idx = stdout.find('CN=')
        if idx > 0:
            self.add_fact('certificate-common-name', stdout[idx+3:].strip())
        (code, stdout, stderr) = self.doit(['x509', '-noout', '-enddate'], cert)
        datestr = stdout.strip().split('=')[1]
        datenow = datetime.datetime.now()
        dateexp = datetime.datetime.strptime(datestr, '%b %d %H:%M:%S %Y %Z')
        self.add_fact('certificate-days-till-expiration', (dateexp-datenow).days)


    def protocol_tls12(self):
        (code, stdout, stderr) = self.connect('-tls1_2')
        cipher = self._get_cipher(stdout)
        self.add_fact('protocol-tls12', cipher)

    def protocol_tls11(self):
        (code, stdout,stderr) = self.connect('-tls1_1')
        cipher = self._get_cipher(stdout)
        self.add_fact('protocol-tls11', cipher)

    def protocol_tls10(self):
        (code, stdout,stderr) = self.connect('-tls1')
        cipher = self._get_cipher(stdout)
        self.add_fact('protocol-tls10', cipher)

    def protocol_ssl3(self):
        (code, stdout,stderr) = self.connect('-ssl3')
        cipher = self._get_cipher(stdout)
        self.add_fact('protocol-ssl3', cipher)

    def protocol_ssl2(self):
        (code, stdout, stderr) = self.connect('-ssl2')
        cipher = self._get_cipher(stdout)
        self.add_fact('protocol-ssl2', cipher)

    def _get_cipher(self, stdout):
        cipher = None
        for line in stdout.split("\n"):
            if 'Cipher    :' in line:
                cipher = line.split(':')[1].strip()
                if cipher == '0000':
                    cipher = None
                break
        return cipher

    def cipher_suites(self, suites):
        for suite in suites:
            (code, stdout, stderr) = self.connect('-cipher', suite)
            self.add_fact('cipher-suite-' + suite, code == 0)

    def cipher_suites_tls12(self):
        if not self.get_fact('protocol-tls12', False):
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

    def test(self):
        self.smoke()
        if self.certificate() == 1:
            return
        self.protocol_tls12()
        self.protocol_tls11()
        self.protocol_tls10()
        self.protocol_ssl3()
        self.protocol_ssl2()
        self.cipher_suites_tls12()
        self.cipher_suites_ssl()

def sslassert_test(target, tests, openssl=None):
    sf = sslassert(target, openssl=openssl)
    sf.check(tests)


if __name__ == '__main__':
    import sys
    target = sys.argv[1]
    if ':' not in target:
        target += ':443'

    import json
    sf = sslassert(target, openssl = ['timeout', '10', 'openssl'])
    sf.test()

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


