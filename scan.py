#!/usr/bin/env python

import sys
import subprocess
import time
count = 0
start = 345

def scan(host, rank):
        cmd = "OPENSSL=/usr/local/ssl/bin/openssl timeout 60 ./sslfacts.sh {0} > tmp/{1:0>8d}-{0}.txt".format(host,int(rank))
        print cmd
        returncode = subprocess.call(cmd, shell=True)
        if returncode != 0:
            cmd = "echo FAIL >>  tmp/{0:0>8d}-{1}.txt".format(rank, host)
            subprocess.call(cmd, shell=True)
            print "FAIL"

with open('./top-1m.csv', 'r') as fd:
    for line in fd:
        count += 1
        rankstr,host = line.strip().split(',')
        rank = int(rank)

        if count < start:
            continue
        t0 = time.time()

        scan(host, rank)

        # try with WWW
        newhost = host
        if not host.startswith('www'):
            newhost = 'www.' + host
            scan(newhost, rank)

        t1 = time.time()
        print "{0} took {1}".format(host, t1-t0)
