#!/usr/bin/env python

"""
Fast fact generation and assertions for SSL/TLS (https) servers
https://github.com/client9/sslassert
"""

import subprocess
import logging
import datetime

class sshassert(object):
    def __init__(self, sshargs = None):
        if sshargs is None:
            self.ssh = ['ssh', ]
        else:
            self.ssh = sshargs

        """
        /opt/local/bin/ssh -V
        OpenSSH_6.2p2, OpenSSL 1.0.1e 11 Feb 2013
        """

        args = self.ssh[:]
        args.append('-V')
        sock = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr =  sock.communicate()
        self.client_version = stderr.strip()

    def connect(self, host, *args):
        cmd = self.ssh[:]
        cmd += ['-F./ssh_config', '-v', '-v', '-v']
        cmd += args
        cmd.append(host)
        sock = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr =  sock.communicate()
        return stderr


    def smoke(self, host):
        """
nickg-air11:sslassert nickg$ ssh -F./ssh_config -v secure.iponweb.net
OpenSSH_5.9p1, OpenSSL 0.9.8x 10 May 2012
debug1: Reading configuration data ./ssh_config
debug1: ./ssh_config line 20: Applying options for *
debug1: Connecting to secure.iponweb.net [195.16.45.5] port 22.
debug1: Connection established.
debug1: identity file ./empty type -1
debug1: identity file ./empty-cert type -1
debug1: Remote protocol version 2.0, remote software version OpenSSH_5.1p1 Debian-5
debug1: match: OpenSSH_5.1p1 Debian-5 pat OpenSSH*
debug1: Enabling compatibility mode for protocol 2.0
debug1: Local version string SSH-2.0-OpenSSH_5.9
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: server->client aes128-ctr hmac-md5 none
debug1: kex: client->server aes128-ctr hmac-md5 none
debug1: SSH2_MSG_KEX_DH_GEX_REQUEST(1024<1024<8192) sent
debug1: expecting SSH2_MSG_KEX_DH_GEX_GROUP
debug1: SSH2_MSG_KEX_DH_GEX_INIT sent
debug1: expecting SSH2_MSG_KEX_DH_GEX_REPLY
vdebug1: Server host key: RSA 8c:1c:39:5a:bf:47:26:30:65:aa:29:b2:f9:bc:0b:3c
Warning: Permanently added 'secure.iponweb.net' (RSA) to the list of known hosts.
debug1: ssh_rsa_verify: signature correct
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug1: SSH2_MSG_NEWKEYS received
debug1: Roaming not allowed by server
debug1: SSH2_MSG_SERVICE_REQUEST sent
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,password
debug1: Next authentication method: publickey
debug1: Trying private key: ./empty
        """

        yield ('ssh_meta_client', self.client_version)

        lines = self.connect(host).split("\n")

        for i in range(len(lines)):
            line = lines[i].strip()
            if line != 'debug2: kex_parse_kexinit: first_kex_follows 0':
                continue
            i += 1
            line = lines[i].strip()
            if line != 'debug2: kex_parse_kexinit: reserved 0':
                continue

            i += 1
            #yield('ssh-kex', lines[i].split(': ')[2].strip())
            parts = lines[i].split(': ')[2].strip().split(',')
            for j,v in enumerate(parts):
                yield('ssh_keyexchange_' + v, j+1)
            i += 1
            #yield('ssh-host-key', lines[i].split(': ')[2].strip())
            parts = lines[i].split(': ')[2].strip().split(',')
            for j,v in enumerate(parts):
                yield('ssh_publickey_' + v, j+1)
            i += 1
            parts = lines[i].split(': ')[2].strip().split(',')
            for j,v in enumerate(parts):
                yield('ssh_cipher_' + v, j+1)
                if j+1 < 10:
                    val = '0' + str(j+1)
                else:
                    val = str(j+1)
                yield('ssh_cipher-order-' + val, v)

            i += 1
            #yield('ssh_server_host_ciphers2', lines[i].split(': ')[2].strip())
            i += 1
            parts = lines[i].split(': ')[2].strip().split(',')
            for j,v in enumerate(parts):
                yield('ssh_mac_' + v, j+1)
                yield('ssh_mac-order-' + str(j+1), v)

            i += 1
            #yield('ssh_server_host_mac2', lines[i].split(': ')[2].strip())
            i += 1
            parts = lines[i].split(': ')[2].strip().split(',')
            for j,v in enumerate(parts):
                yield('ssh_compression_' + v, j+1)
            #yield('ssh_compression', lines[i].split(': ')[2].strip())
            i += 1
            #yield('ssh_server_host_compression2', lines[i].split(': ')[2].strip())
            break

        for line in lines:
            if not line.startswith('debug1:'):
                continue

            #if 'debug1: Remote protocol version 2.0, remote software version OpenSSH_5.1p1 Debian-5'
            if 'Remote protocol version' in line:
                parts = line.split()
                val = parts[4].replace(',', '')
                yield('ssh_protocol_version', float(val))
                # do NOT continue

            if 'remote software version' in line:
                sshserver = line.split('remote software version')[1].strip()
                yield ('ssh_server_version', sshserver)
                continue

            if 'Server host key' in line:
                parts = line.split(':', 2)
                yield ('ssh_server_host_key', parts[2].strip())
                continue

            if 'kex: client->server' in line:
                parts = line.split('kex: client->server')[1].strip()
                yield ('ssh_client_key-exchange', parts)


            if 'kex: server->client' in line:
                parts = line.split('kex: server->client')[1].strip()
                yield ('ssh_server_key-exchange', parts)
                continue

            if 'Authentications that can continue' in line:
                parts = line.split(':')
                auths = parts[2].split(',')
                for auth in ('password','publickey', 'keyboard-interactive'):
                    yield ('ssh_authentication_' + auth, auth in parts[2])
                continue

if __name__ == '__main__':
    import sys
    target =sys.argv[1]
    s = sshassert(['/opt/local/bin/ssh',])
    for k,v in s.smoke(target):
        print k,v
