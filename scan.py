#!/usr/bin/env python

import sys
import subprocess
count = 0
start = 345
with open('./top-1m.csv', 'r') as fd:
    for line in fd:
        count += 1
        rank,host = line.strip().split(',')
        if count < start:
            continue
        cmd = "OPENSSL=/usr/local/ssl/bin/openssl timeout 60 ./sslfacts.sh {0} > tmp/{1:0>8d}-{0}.txt".format(host,int(rank))
        print cmd
        returncode = subprocess.call(cmd, shell=True)
        if returncode != 0 and not host.startswith('www'):
            newhost = 'www.' + host
            cmd = "OPENSSL=/usr/local/ssl/bin/openssl timeout 60 ./sslfacts.sh {0}> tmp/{2:0>8d}-{1}.txt".format(newhost,host,int(rank))
            print cmd
            returncode = subprocess.call(cmd, shell=True)
            if returncode != 0:
	        cmd = "echo FAIL >>  tmp/{2:0>8d}-{1}.txt".format(newhost,host,int(rank))
                subprocess.call(cmd, shell=True)
                print "FAIL"
