sslassert
==============

Simple unit tests to make sure your web server is configured correctly under SSL.

It's in `sh` (subset of `bash`).  Why?  It's one file, no
installation, only requires openssl, and basic posix shell stuff.  And
mostly it's calling out to OpenSSL anyways, so why not bash?


sslfacts
--------------

```
export HOSTPORT=www.google.com
export URLPATH=/
source sslassert.sh
```

Will then generate a number of facts based on the site:

* accepted and rejected cipher suites
* protocol support for sslv2 - tls1.2
* various statistics on symmetric and public key cryptography
* various certificate facts
* common problems and attacks

You can see the full fact list by running the sample script

```
./sslfact.sh libinjection.client9.com
```

sslassert
---------------

Then you'll want to test the facts against what your expectations.

The same script below shows how.  You can use any of the bash test
operators (e.g. -gt,-ge,-lt,-le,-ne,-eq, =, !=, > etc)


```
#!/bin/sh

export HOSTPORT=www.google.com
export URLPATH=/

source sslassert.sh

sslassert 'secure-renegotiation               = on'
sslassert 'compression                        = off'
sslassert 'certificate-length               -ge 1024'
sslassert 'protocol-ssl-v2                    = off'
sslassert 'protocol-tls-v12                   = on'
sslassert 'crypto-weak                        = off'
sslassert 'beast-attack                       = off'

exit $SSLASSERT_EXIT
```

and that's it.





Note for later reference:


Certificate chain is not self-signed
------------------------------------

```
Certificate chain
 0 s:/OU=Domain Control Validated/CN=YOUR SERVER HERE
   i:/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./OU=http://certificates.godaddy.com/repository/CN=Go Daddy Secure Certification Authority/serialNumber=1234
 1 s:/C=US/ST=Arizona/L=Scottsdale/O=GoDaddy.com, Inc./OU=http://certificates.godaddy.com/repository/CN=Go Daddy Secure Certification Authority/serialNumber=1234
   i:/C=US/O=The Go Daddy Group, Inc./OU=Go Daddy Class 2 Certification Authority
 2 s:/C=US/O=The Go Daddy Group, Inc./OU=Go Daddy Class 2 Certification Authority
   i:/C=US/O=The Go Daddy Group, Inc./OU=Go Daddy Class 2 Certification Authority
```

Looking at #2 in the chain, you'll see a self-signed cert for
Go-Daddy.  That's normally inside the http-client already, so sending
it is kinda weird, and might cause problems.  It's certainly a waste
of space.
