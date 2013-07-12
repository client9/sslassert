ssl-unit-tests
==============

simple scripts to make sure your web server is configured correctly under SSL.

They are bash scripts that just return 0 if ok, 1 if error (standard
Unix-style).  Adjust as needed.

They require openssl which is available on every OS.

Current tests:

* Certificate chain exists
* SSL v2 is not accepted


