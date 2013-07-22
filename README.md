ssl-unit-tests
==============

simple scripts to make sure your web server is configured correctly under SSL.

They are bash scripts that just return 0 if ok, 1 if error (standard
Unix-style).  Adjust as needed.

They require openssl which is available on every OS.

Current tests:

* Certificate chain exists (definitely required)
* SSL v2 is not accepted (defintely bad)
* SSL Compression is off (leaks info, causes problems)
* TLS 1.0 is accepted (required for general public traffic)
* TLS 1.1 is accepted
* TLS 1.2 is accepted
* Weak Cipher Suites are Rejected
* Certificate chain is not self-signed


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
