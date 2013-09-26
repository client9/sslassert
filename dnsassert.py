#!/usr/bin/env python

import subprocess
import logging
import datetime

def digit(*args):
    cmd = ['dig']
    cmd += args

    sock = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sock.communicate()
    return sock.returncode, stdout, stderr

def dnsfacts(host):
    facts = []
    parts = host.split('.')
    for i in range(len(parts) - 1):
        newhost = '.'.join(parts[i:])
        for val in dnsfacts1(newhost):
            yield val

def dnsfacts1(host):
    code,stdout,stderr = digit('+noquestion', '+noadditional', '+noauthority', '+nostat',
                               '+nocomments', 'mx', host)
    count = 0
    for line in stdout.split("\n"):
        line = line.strip()
        if len(line) == 0:
            continue
        if line[0] == ';':
            continue
        parts = line.split()
        if parts[3] == 'MX':
            count += 1
            yield ('dns_{0}_mx_{1}'.format(host, parts[5]), parts[4])
    yield ('dns_{0}_mx_count'.format(host), count)
    code,stdout,stderr = digit('+noquestion', '+noadditional', '+nostat',
                               '+nocomments', host)
    counta = 0
    countns = 0
    for line in stdout.split("\n"):
        line = line.strip()
        if len(line) == 0:
            continue
        if line[0] == ';':
            continue
        parts = line.split()
        if parts[3] == 'A':
            counta += 1
            yield ('dns_{0}_a_{1}'.format(host, parts[4]), counta)
        elif parts[3] == 'NS':
            countns += 1
            yield ('dns_{0}_ns_{1}'.format(host, parts[4]), countns)
    yield ('dns_{0}_a_count'.format(host), counta)
    yield ('dns_{0}_ns_count'.format(host), countns)

if __name__ == '__main__':
    import sys
    target = sys.argv[1]
    tl = target.lower()
    print tl

    for k,v in dnsfacts(tl):
        print k,v

