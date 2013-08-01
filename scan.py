#!/usr/bin/env python

import sys
import subprocess
import time
count = 0
start = 345
with open('./top-1m.csv', 'r') as fd:
    for line in fd:
        count += 1
        rank,host = line.strip().split(',')
        if count < start:
            continue
        t0 = time.time()

        # try with WWW
        newhost = host
        if not host.startswith('www'):
            newhost = 'www.' + host
        cmd = "OPENSSL=/usr/local/ssl/bin/openssl timeout 60 ./sslfacts.sh {0} > tmp/{1:0>8d}-{2}.txt".format(newhost,int(rank),host)
        print cmd
        returncode = subprocess.call(cmd, shell=True)
        if returncode != 0:
            # try naked domain
            cmd = "OPENSSL=/usr/local/ssl/bin/openssl timeout 60 ./sslfacts.sh {0} > tmp/{1:0>8d}-{0}.txt".format(host,int(rank))
            print cmd
            if returncode != 0:
                cmd = "echo FAIL >>  tmp/{1:0>8d}-{2}.txt".format(int(rank), host)
                subprocess.call(cmd, shell=True)
                print "FAIL"
        t1 = time.time()
        print "{0} took {1}".format(host, t1-t0)
