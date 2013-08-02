#!/usr/bin/env python

from multiprocessing import Process, Queue
from Queue import Empty
import sys
import subprocess
import time

def scan(rank, host):

    cmd = "OPENSSL=/usr/local/ssl/bin/openssl timeout 60 ./sslfacts.sh {0} > tmp/{1:0>8d}-{0}.txt".format(host,int(rank))
    #cmd = "./sslfacts.sh {0} > tmp/{1:0>8d}-{0}.txt".format(host,int(rank))
    print cmd
    returncode = subprocess.call(cmd, shell=True)
    if returncode != 0:
        cmd = "echo FAIL >>  tmp/{0:0>8d}-{1}.txt".format(rank, host)
        subprocess.call(cmd, shell=True)
        print "FAIL"

def worker(q):
    try:
        while True:
            msg = q.get(block=True, timeout=1)
            scan(*msg)
    except Empty:
        print "Working done, exiting"

if __name__ == '__main__':
    count = 0
    start = 0
    stop = 10000
    num_workers = 4

    q = Queue()
    with open('./top-1m.csv', 'r') as fd:
        for line in fd:
            count += 1
            if count < start:
                continue
            if count > stop:
                break
            rankstr,host = line.strip().split(',')
            rank = int(rankstr)
            q.put( (rank, host) )

            if not host.startswith('www'):
               q.put( (rank, 'www.' + host) )

    workers = [ Process(target=worker, args=(q,)) for i in range(num_workers) ]

    # start them
    for w in workers:
        w.start()

    # wait for them to finish
    for w in workers:
        w.join()
