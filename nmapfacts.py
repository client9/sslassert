#!/usr/bin/env python
from lxml import etree
import subprocess

class nmapassert(object):
    def __init__(self, cmd = None):
        if cmd is None:
            self.exe = ['nmap', ]
        else:
            self.exe = cmd

        """
        /opt/local/bin/ssh -V
        OpenSSH_6.2p2, OpenSSL 1.0.1e 11 Feb 2013
        """

        args = self.exe[:]
        args.append('-V')
        sock = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr =  sock.communicate()
        #self.client_version = stderr.strip()

    def connect(self, host, *args):
        cmd = self.exe[:]
        cmd += ['-Pn', '-T3', '-oX', '-']
        cmd.append(host)
        sock = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout,stderr =  sock.communicate()
        return stdout

    def smoke(self, host):
        #yield ('ports_meta_client', self.client_version)
        lines = self.connect(host)
        xml = etree.fromstring(lines)
        counts = {}
        for el in xml.iter('port'):
            state = el[0].get('state')
            if state in counts:
                counts[state] += 1
            else:
                counts[state] = 1
            yield ('ports_' + el.get('protocol') + '_' + el.get('portid'), el[0].get('state'))
        for k,v in counts.iteritems():
            yield ('ports_count_' + k, str(v))

if __name__ == '__main__':
    import sys
    target =sys.argv[1]
    s = nmapassert()
    for k,v in s.smoke(target):
        print k,v
