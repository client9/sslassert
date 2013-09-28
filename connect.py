#!/usr/bin/env python
import paramiko
import socket
import logging
import base64
from StringIO import StringIO


def sshfacts(host, port=22):
    buffer      = StringIO()
    logHandler  = logging.StreamHandler(buffer)
    paramiko.common.logging.basicConfig(
        level=paramiko.common.DEBUG,
        format='%(name)s:%(message)s',
        stream=buffer
    )

    s = socket.socket(
        socket.AF_INET, socket.SOCK_STREAM)

    s.connect((host, port))
    tx = paramiko.Transport(s)

    junk = tx.start_client()

    serverkey = tx.get_remote_server_key()
    md5key = serverkey.get_fingerprint()


    so = tx.get_security_options()


    authmethods = ['none']
    try:
        tx.auth_none('nothing')
    except paramiko.BadAuthenticationType, e:
        authmethods = e.allowed_types

    keys = (
        'kex-algos',
        'server-encrypt',
        'server-key',
        'server-compress',
        'server-mac',
        'server-lang'
    )
    for line in buffer.getvalue().split("\n"):
        if not line.startswith('paramiko.transport:'):
            continue
        parts = line.split(':',2)
        if parts[1] == 'Banner':
            yield ('ssh_banner', parts[2].strip())
        elif parts[1] in keys:
            algs = parts[2].split(',')
            if len(algs) > 1 and algs[0] != '':
                for i, alg in enumerate(algs):
                    yield('ssh_{0}-order_{1:02}'.format(parts[1], i+1), alg)
                    yield('ssh_{0}_{1}'.format(parts[1],  alg), i+1)


    for auth in authmethods:
        yield ('ssh_auth_{0}'.format(auth), True)

    yield ('ssh_server-fingerprint', serverkey.get_name() + ' ' + ":".join("{0:x}".format(ord(c)) for c in md5key))


if __name__ == '__main__':
    import sys
    import json
    host = sys.argv[1]
    facts = {}
    for k in sshfacts(host):
        facts[k[0]] = k[1]
    print json.dumps(facts, indent=2, sort_keys=True)

