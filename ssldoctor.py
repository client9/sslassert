#!/usr/bin/env python
import subprocess
import sys

# generated from openssl ciphers 'ALL:COMPLEMENTOFALL'
OPENSSLSUITES = set("""ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:SRP-DSS-AES-256-CBC-SHA:SRP-RSA-AES-256-CBC-SHA:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:AECDH-AES256-SHA:SRP-AES-256-CBC-SHA:ADH-AES256-GCM-SHA384:ADH-AES256-SHA256:ADH-AES256-SHA:ADH-CAMELLIA256-SHA:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:ECDH-RSA-AES256-SHA:ECDH-ECDSA-AES256-SHA:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:CAMELLIA256-SHA:PSK-AES256-CBC-SHA:ECDHE-RSA-DES-CBC3-SHA:ECDHE-ECDSA-DES-CBC3-SHA:SRP-DSS-3DES-EDE-CBC-SHA:SRP-RSA-3DES-EDE-CBC-SHA:EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:AECDH-DES-CBC3-SHA:SRP-3DES-EDE-CBC-SHA:ADH-DES-CBC3-SHA:ECDH-RSA-DES-CBC3-SHA:ECDH-ECDSA-DES-CBC3-SHA:DES-CBC3-SHA:DES-CBC3-MD5:PSK-3DES-EDE-CBC-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:SRP-DSS-AES-128-CBC-SHA:SRP-RSA-AES-128-CBC-SHA:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-SEED-SHA:DHE-DSS-SEED-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:AECDH-AES128-SHA:SRP-AES-128-CBC-SHA:ADH-AES128-GCM-SHA256:ADH-AES128-SHA256:ADH-AES128-SHA:ADH-SEED-SHA:ADH-CAMELLIA128-SHA:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:ECDH-RSA-AES128-SHA:ECDH-ECDSA-AES128-SHA:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA:SEED-SHA:CAMELLIA128-SHA:IDEA-CBC-SHA:IDEA-CBC-MD5:RC2-CBC-MD5:PSK-AES128-CBC-SHA:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:AECDH-RC4-SHA:ADH-RC4-MD5:ECDH-RSA-RC4-SHA:ECDH-ECDSA-RC4-SHA:RC4-SHA:RC4-MD5:RC4-MD5:PSK-RC4-SHA:EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:DES-CBC-SHA:DES-CBC-MD5:EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:EXP-ADH-DES-CBC-SHA:EXP-DES-CBC-SHA:EXP-RC2-CBC-MD5:EXP-RC2-CBC-MD5:EXP-ADH-RC4-MD5:EXP-RC4-MD5:EXP-RC4-MD5:ECDHE-RSA-NULL-SHA:ECDHE-ECDSA-NULL-SHA:AECDH-NULL-SHA:ECDH-RSA-NULL-SHA:ECDH-ECDSA-NULL-SHA:NULL-SHA256:NULL-SHA:NULL-MD5""".strip().split(':'))

OPENSSLTOKENS = set([
    '@STRENGTH',
    'DEFAULT',
    'COMPLEMENTOFDEFAULT',
    'ALL',
    'COMPLEMENTOFALL',
    'HIGH',
    'MEDIUM',
    'LOW',
    'EXP',
    'EXPORT',
    'EXPORT40',
    'EXPORT56',
    'eNULL',
    'NULL',
    'aNULL',
    'kRSA',
    'RSA',
    'kEDH',
    'kDHr',
    'kDHd',
    'aRSA',
    'aDSS',
    'DSS',
    'aDH',
    'kFZA',
    'aFZA',
    'eFZA',
    'FZA',
    'TLSv1',
    'SSLv3',
    'SSLv2',
    'DH',
    'ADH',
    'AES',
    'CAMELLIA',
    '3DES',
    'DES',
    'RC4',
    'RC2',
    'IDEA',
    'SEED',
    'MD5',
    'SHA1',
    'SHA',
    'aGOST',
    'aGOST01',
    'aGOST94',
    'kGOST',
    'GOST94',
    'GOST89MAC',
# NOT DOCUMENTED
    'EDH'
])

MSG = {
    'OPENSSL_BAD_INPUT': ['RED', 'Suite string was not able to be parsed'],
    'OPENSSL_TAGS'  : ['YELLOW', "Using OpenSSL's tags is not recommend"],
    'OPENSSL_UNKNOWN_TOKEN': ['RED', 'Unknown OpenSSL Token found {1}'],
    'SUITE_NULL'    : ['RED', "Use of NULL suites is dangerous"],
    'SUITE_ECDHE_ECDSA': ['RED', 'Highly unlikely you have a ECHDE_ECDSA certificate'],
    'SUITE_DSA'     : ['RED', 'Highly unlikely you have a DSA certificate'],
    'SUITE_CAMELLIA': ['YELLOW', 'CAMELLIA Suite highly unlikely to be required'],
    'SUITE_IDEA'    : ['RED', 'The IDEA cipher is effectively deprecated'],
    'SUITE_SEED'    : ['RED', 'The SEED cipher is effectively deprecated'],
    'SUITE_EXPORT'  : ['RED', '"Export Grade" cryptography found (weak and deprecated)'],
    'SUITE_DES'     : ['RED', '56-Bit DES cryptography found'],
    'SUITE_SRP'     : ['RED', 'Old SRP cryptography found, unlikely to be used and likely obsolete'],
    'SUITE_AECDH'   : ['RED', 'Anonymous DH is insecure, elliptic curve version unlikely to be implemented by clients'],
    'SUITE_ADH'     : ['RED', 'Anonymous DH is insecure, and this suite is unlikely to be used by clients'],
    'SUITE_PSK'     : ['RED', 'PSK suites are not usefull in public SSL'],
    'SUITE_ECDH'    : ['RED', 'Fixed Elliptic-Curve DH unlikely to be preferred'],
    'SUITE_RC2'     : ['RED', 'Weak RC2 cryprography found'],
    'SUITE_MD5'     : ['RED', 'Weak and deprecated MD5 cryprography found'],
    'ECFUNCTIONS_REDHAT': ['NOTE', "You using ECDH- or ECDHE- suites.  On RedHat-based operating systems including RHEL, CentOS, Fedora, and Amazon-Linux, these functions are missing.  It's ok to have them listed, but they will not be enabled."],
    'ECDHE_OPENSSL': ['NOTE', 'You are using ECDHE- suites.  It is very important you are using OpenSSL >= 1.0.0e'],
    'DUPLICATE_SUITES': ['RED', 'Duplicate suites found, may cause unexpected behavior'],

    'WINDOWSXP_FIPS_YES': ['GREEN', "Window XP, IE <= 8, FIPS-client compatible"],
    'WINDOWSXP_FIPS_NO': ['YELLOW', "Uses running Window XP, IE <= 8 under certain configurations (FIPS) may be not able to access your site"],
    'WINDOWSXP_NO': ['RED', "Users running Window XP, IE <= 8 are unlikely to be able to access your site"],
    'BASIC_AES_YES': ['GREEN', "Has basic AES support"],
    'BASIC_AES_NO': ['RED', "Missed AES128-SHA or AES256-SHA, needed for basic compatibility"],
    "AES_TLS12_YES": ['GREEN', "Has basic AES TLSv1.2 support"],
    "AES_TLS12_NO":  ['RED', "Missing AES TLSv1.2 support.  Even if your server doesn't currently support TLSv1.2 it is safe to add these ciphers now.  Once you upgrade, then will be enabled"],
    'TLS12_MISSING': ['RED', 'There are no TLSv1.2 cipher suites enabled'],
    'SUITES_OUT_OF_ORDER': ['RED', 'Suites are out of order {1} should be before {2}'],
    'BEAST_ATTACK': ['RED', "Beast attack is possible since {1} is before a RC4-based suite"]
}

class SSLDoctor(object):

    def __init__(self):
        pass

    def validate_openssl_string(self, astr):
        parts = astr.strip().split(':')
        for suite in parts:
            if suite[0] in ('+', '!', '-'):
                suite = suite[1:]
                if '+' in suite:
                    names = suite.split('+')
                else:
                    names = ( suite, )
                for token in names:
                    # not exactly right
                    token = token.replace('@STRENGTH', '')

                    # I can't valid GOST since i don't have an engine to test
                    if token is not '' and 'GOST' not in token:
                        if token not in OPENSSLTOKENS and  token not in OPENSSLSUITES:
                            self.messages.append( ('OPENSSL_UNKNOWN_TOKEN', token) )
                            return

    def is_tls12(self, suite):
        """ Sleazy way of determining if a suite is TLSv1.2 """
        return '-GCM-' in suite or 'SHA256' in suite or 'SHA384' in suite

    def analyze(self, opensslstring):
        self.original = opensslstring.strip()
        self.suites_orig = []
        self.suites_new = []
        self.messages = []

        try:
            self.suites_orig_text = subprocess.check_output(['openssl', 'ciphers', self.original])
            self.suites_orig_text =  self.suites_orig_text.strip()
        except subprocess.CalledProcessError:
            self.messages.append('OPENSSL_BAD_INPUT')
            return

        self.validate_openssl_string(self.original)

        self.suites_orig = self.suites_orig_text.split(':')

        if self.original != self.suites_orig_text:
            self.messages.append( ('OPENSSL_TAGS', ) )

        tests = [
            [ 'NULL', 'SUITE_NULL'],
            [ 'RC2', 'SUITE_RC2'],
            [ 'ECDHE-ECDSA-', 'SUITE_ECDHE_ECDSA'],
            [ '-DSS-', 'SUITE_DSA'],
            [ 'CAMELLIA', 'SUITE_CAMELLIA'],
            [ 'IDEA', 'SUITE_IDEA'],
            [ 'SEED', 'SUITE_SEED'],
            [ 'EXP-', 'SUITE_EXPORT'],
            [ 'DES-CBC-', 'SUITE_DES'],
            [ 'SRP-', 'SUITE_SRP'],
            [ 'AECDH-', 'SUITE_AECDH'],
            [ 'ADH-', 'SUITE_ADH'],
            [ 'PSK-', 'SUITE_PSK'],
            [ 'ECDH-', 'SUITE_ECDH'],
            [ 'MD5', 'SUITE_MD5']
        ]

        for t in self.suites_orig:
            self.suites_new.append(t)
            print t

        # check for bad stuff
        for t in tests:
            self.cleanup(t[0], t[1])

        # check for RedHat *server* problems
        if 'ECDHE-' in self.suites_orig_text or 'ECDH-' in self.suites_orig_text:
            self.messages.append( ("ECFUNCTIONS_REDHAT",) )

        # tip on openssl version
        if 'ECDHE-' in self.suites_orig_text:
            self.messages.append( ('ECDHE_OPENSSL',))

        suiteset = set(self.suites_orig)
        if len(suiteset) != len(self.suites_orig):
            self.messages.append( ("DUPLICATE_SUITES",))
            # now remove duplicates
            newtokens = []
            suiteset = set()
            for t in self.suites_new:
                if t not in suiteset:
                    newtokens.append(t)
                    suiteset.add(t)
            self.suites_new = newtokens

        tls12 = False
        for t in self.suites_orig:
            if 'SHA384' in t or 'SHA256' in t:
                tls12= True
                break
        if not tls12:
            self.messages.append( ("TLS12_MISSING",) )

        # check for missing stuff
        if 'DES-CBC3-SHA' in self.suites_orig:
            self.messages.append( ("WINDOWSXP_FIPS_YES", ))
        else:
            if 'RC4-SHA' not in self.suites_orig:
                self.messages.append(('WINDOWSXP_NO',))
            else:
                self.messages.append(("WINDOWSXP_FIPS_NO",))

        if 'AES128-SHA' in self.suites_orig and \
           'AES256-SHA' in self.suites_orig:
            self.messages.append( ("BASIC_AES_YES",) )
        else:
            self.messages.append( ("BASIC_AES_NO",) )

        if 'AES128-SHA256' in self.suites_orig and \
           'AES256-SHA256' in self.suites_orig and \
           'AES128-GCM-SHA256' in self.suites_orig and \
           'AES256-GCM-SHA384' in self.suites_orig:
            self.messages.append( ("AES_TLS12_YES",) )
        else:
            self.messages.append( ("AES_TLS12_NO", ))

        # check that 3DES is always after AES suites, for performance reasons
        self.isbefore('AES128-SHA', 'DES-CBC3-SHA')
        self.isbefore('AES256-SHA', 'DES-CBC3-SHA')
        self.isbefore('ECDHE-RSA-AES128-SHA', 'ECDHE-RSA-DES-CBC3-SHA')
        self.isbefore('ECDHE-RSA-AES256-SHA', 'ECDHE-RSA-DES-CBC3-SHA')

        # GCM is perferred above all others, why? cause it's better and faster
        self.isbefore('AES128-GCM-SHA256', 'AES128-SHA256')
        self.isbefore('AES256-GCM-SHA384', 'AES256-SHA384')
        self.isbefore('AES128-GCM-SHA256', 'AES128-SHA')
        self.isbefore('AES256-GCM-SHA384', 'AES256-SHA')
        self.isbefore('ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA256')
        self.isbefore('ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-SHA384')
        self.isbefore('DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-SHA256')
        self.isbefore('DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-SHA256')

        # ECDHE is preferred over DHE, cause it's faster, and FIPS compliant
        self.isbefore('ECDHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-GCM-SHA256')
        self.isbefore('ECDHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-GCM-SHA384')
        self.isbefore('ECDHE-RSA-AES128-SHA256', 'DHE-RSA-AES128-SHA256')
        self.isbefore('ECDHE-RSA-AES256-SHA384', 'DHE-RSA-AES256-SHA256')
        self.isbefore('ECDHE-RSA-AES128-SHA', 'DHE-RSA-AES128-SHA')
        self.isbefore('ECDHE-RSA-AES256-SHA', 'DHE-RSA-AES256-SHA')

        # check for beast
        for s in self.suites_orig:
            if self.is_tls12(s):
                continue
            # this is first non TLSv12 suite
            if 'RC4' not in s:
                self.messages.append( ('BEAST_ATTACK', s,) )
                break

        for msg in self.messages:
            mdata = MSG[msg[0]]
            mtext = mdata[1].format(*msg)
            print "{0}: {1}".format(mdata[0], mtext)

        for t in self.suites_new:
            print t

    def isbefore(self, suite1, suite2):
        try:
            i1 = self.suites_orig.index(suite1)
            i2 = self.suites_orig.index(suite2)
            if (i1 > i2):
                self.messages.append( ('SUITES_OUT_OF_ORDER', suite1, suite2) )
        except ValueError:
            pass

    def cleanup(self, tag, msgtag):
        if tag not in self.suites_orig_text:
            return
        self.messages.append( (msgtag, ) )
        newtokens = []
        for t in self.suites_new:
            if tag not in t:
                newtokens.append(t)

        self.suites_new = newtokens

if __name__ == '__main__':
    arg = sys.argv[1]
    ssldoc = SSLDoctor()
    ssldoc.analyze(arg)

