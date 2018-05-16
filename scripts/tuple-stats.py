#! /usr/bin/python

import sys

tuples = set()

with open(sys.argv[1], 'r') as fi:
    for i in fi.readlines():
        t = ''
        rule = i.split(' ')
        t += rule[0].split('/')[1]
        t += ','
        t += rule[1].split('/')[1]
        t += ','
        t += rule[2].split('/')[1]
        t += ','
        t += rule[3].split('/')[1]
        tuples.add(t)

print tuples
print 'tuple number:', len(tuples)
