
Blackbox Checkers
==================

* [SSLLabs](https://sslabs.com) (Qualys)
* [GlobalSign](https://sslcheck.globalsign.com/en_US) (powered by SSLLabs, but has additional information)

Various References, both good and Bad!
======================================

[OCSP Stapling in Firefox](http://blog.mozilla.org/security/2013/07/29/ocsp-stapling-in-firefox/) 2013-07-29

OSCP Stapling lands on nightly.  I guess to be put in next release?

[having a lot of troubles trying to get AES-NI working](http://openssl.6102.n7.nabble.com/having-a-lot-of-troubles-trying-to-get-AES-NI-working-td44285.html) 2013-04-13

Reveals the Magic Command to turn off AES-NI (Special Intel CPU instructions to speed up AES)

'''
You can disable AES-NI detection with the environment variable:

OPENSSL_ia32cap=~0x200000200000000
'''

'''
Compare the following results:
OPENSSL_ia32cap="~0x200000200000000" openssl speed -elapsed -evp aes-128-cbc
openssl speed -elapsed -evp aes-128-cbc
'''

Lots of interesting bits.

(Supported Cipher Suites when FIPS Level 1 Support is Enabled and Disabled)[http://www.juniper.net/techpubs/en_US/sa/topics/reference/general/secure-access-fips-supported-ciphers.html] 2013-06-05

From Juniper Router documentation.  I hope they would know.

* RSA and ECDHE_RSA-* are FIPS
* 3DES_EDE and AES (including GSM versions)
* not supported is DHE-* (regular discrete log DH)

[5 easy tips to accelerate SSL](http://unhandledexpression.com/2013/01/25/5-easy-tips-to-accelerate-ssl/) 2013-01-25

Almost everything in this is wrong. Final recommendation is

```
ALL:!ADH:!EXP:!LOW:!RC2:!3DES:!SEED:!RC4:+HIGH:+MEDIUM
```

(Attack of the week: RC4 is kind of broken)[http://blog.cryptographyengineering.com/2013/03/attack-of-week-rc4-is-kind-of-broken-in.html]

Makes a claim that RC4 should be discontinued.  Surely everyone agrees
on this.  However right now the BEAST attack is practical now, while
the RC4 attack is "almost doable".  Unfortuantely, there is no good
solution right now as few clients support TLS 1.1 which would allow
the option to drop TLSv1 and SSLv3.

There is no server that allows for per-protocol support.

SSLv3: list..
TLSv1: list...
TLSv1.1: list...
TLSv1.2: list...

Instead it's all lumped together.




[Ideal OpenSLL Configuration for Apache](http://feeding.cloud.geek.nz/posts/ideal-openssl-configuration-for-apache/) 2012?

Recommends:
'''
RC4-SHA:HIGH:!kEDH
'''

[Annex A:FIPS PUB 140-2 Draft](http://csrc.nist.gov/publications/fips/fips140-2/fips1402annexa.pdf)
2012-05-30

WORK IN PROGRESS

FIPS requirements:

* Symmetric encryption: AES, 3DES (3 key Triple DES)
* Asymmetric encryption: DSS+DSA, RSA and RCDSA
* Secure Hash: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256
* Message Authentication: 3DES, AES+SHS

Not clear on key agreement protocols and FIPS.  NIST has standards but
not clear if they are FIPS or not.

[SSL/TLS & Perfect Forward Secrecy](http://vincent.bernat.im/en/blog/2011-ssl-perfect-forward-secrecy.html) 2011

Good statistics:

* DHE2048 3x slower than RSA2048.  Ugh.
* ECHDE (curve unknown) only 25% increase over RSA2048 for server-side computation
* ECDHE-64 (curve unknown)  only 15% increase over RSA2048 for server-side computation

Micro-bench marking tools: https://github.com/vincentbernat/ssl-dos/blob/master/server-vs-client.c

[Forward secrecy for Google HTTPS](https://www.imperialviolet.org/2011/11/22/forwardsecret.html) 2011-11-11

Good information on Google's implementation of ECDHE

* ECDHE-RSA-RC4-SHA default cipher for Google.
* constant-time implementations of P-224, P-256 and P-521 for OpenSSL
* OpenSSL 1.0.0e fixes a lot of bugs
* P-256 estimate to be equivalent of 3248-bit RSA key

[Protecting Data for the Long Term](http://googleonlinesecurity.blogspot.jp/2011/11/protecting-data-for-long-term-with.html) 2011-11-11

Google's annoucment on forward secrecy.

> Any browser that supports ECDHE-RC4-SHA will get forward secrecy with
> Google HTTPS sites. There's nothing Chrome or Firefox specific on the
> server side. A browser that supports only DHE-RC4-SHA will *not* get
> forward secrecy because we don't support EDH for speed reasons.

Summary:
* Explicitly mentioned that "IE doesn’t support the combination of ECDHE and RC4"
* Comments add that "EDH-" ..?

[SSL computational DoS mitigation](http://vincent.bernat.im/en/blog/2011-ssl-dos-mitigation.html) 2011

Mostly focused on DoS issues, but has nice performance chart.

[TLS/SSL Hardening and Compatibility Report 2011](http://www.g-sec.lu/sslharden/SSL_comp_report2011.pdf) 2011

Page 14 indicated Opera 10 and Safari 4 support DHE-RSA but do not support ECDHE-RSA.

Page 19: no need to enable SSLv2 and SSLv3 for IIS7.5

[A quick look over some browsers and their SSL/TLS implementations](http://www.carbonwind.net/blog/post/A-quick-look-over-some-browsers-and-their-SSLTLS-implementations.aspx)

Summary: A range of browsers from IE6 Windows XP, Chrome 9, Opera 11, Safari 5, Firefox 3.6

Common to all tested browsers:

* TLS_RSA_WITH_RC4_128_MD5
* TLS_RSA_WITH_RC4_128_SHA
* TLS _RSA_WITH_3DES_EDE_CBC_SHA

Implies there is no need to support TLS_RSA_WITH_RC4_128_MD5.

> TLS 1.0 is supported and enabled by default on the most browsers
> from the ones tested; exception makes Internet Explorer 6 which
> does not enable TLS 1.0 by default.

Again, if you do not need IE6 support, one can turn off SSL v3.

> Some DHE_RSA based cipher suites are supported by all the tested
> browsers except the ones using Schannel(which does not support
> DHE_RSA based cipher suites). ...  Some ECDHE_RSA or ECDHE_ECDSA
> based cipher suites are also supported by some browsers; exceptions
> being Opera, the browsers using Schannel NT 5.1.2600 and Safari on
> Mac OS X 10.5.8, plus the Firefox versions shipped with some Linux
> distros(Fedora, Red Hat Enterprise Linux).

Translation: DHE is needed for forward-secrey for Firefox on Red Hat
distributions, and older versions of Safari.

[How secure is the secure web? SSL/TLS-server stats, part 2](http://my.opera.com/securitygroup/blog/2010/06/02/how-secure-is-the-secure-web-ssl-tls-server-stats-part-2) 2010-06-02

> According to our "TLS prober", around 1% of servers accept only
> this cipher suite [RC4-MD5]. This is a sizable portion of servers,
> and even includes at least some important online payment services
> (!), so we will have to wait a bit longer before we disable this
> cipher suite."

However note this is on client-side support talking to servers that
only use RC4-MD5.  As server, I still can't find any statistics on
clients that _only_ use RC4-MD5.


(SSL cipher settings)[http://www.skytale.net/blog/archives/22-SSL-cipher-setting.html] 2009-09-13

This page ranked high in a search.  It's an old recommendation.

'''
TLSv1+HIGH:!SSLv2:RC4+MEDIUM:!aNULL:!eNULL:!3DES:@STRENGTH
'''
