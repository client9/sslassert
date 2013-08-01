#!/usr/bin/env python

import sys
import subprocess
count = 0
start = 0
with open('./top-1m.csv', 'r') as fd:
    for line in fd:
        count += 1
        rank,host = line.strip().split(',')
        if count < start:
            continue
        cmd = "./sslfacts.sh {0} > tmp/{1:0>8d}-{0}.txt".format(host,int(rank))
        print cmd
        returncode = subprocess.call(cmd, shell=True)
        if returncode != 0 and not host.startswith('www'):
            newhost = 'www.' + host
            cmd = "./sslfacts.sh {0}> tmp/{2:0>8d}-{1}.txt".format(newhost,host,int(rank))
            print cmd
            returncode = subprocess.call(cmd, shell=True)
