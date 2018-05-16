#! /usr/bin/python

import sys
from random import randint

ORIGINAL = 10
UPDATE = 1
ALL = 11

def main():
    rules = []
    rules_orgnl = []
    rules_updt = []

    with open('%s' % sys.argv[1]) as fi:
        for i in fi.readlines():
            rules.append(i[:-1])

    if len(rules[0].split(' ')) is 9:
        r_id = 0
        for i in xrange(0, len(rules)):
            r_id += 1
            rules[i] = rules[i] + ' ' + str(r_id)
        with open('%s' % sys.argv[1], 'w') as fo:
            for r in rules:
                fo.write('%s\n' % r)

    for i in xrange(0, len(rules) - 1):
        if randint(1, ALL) <= UPDATE:
            rules_updt.append(rules[i])
        else:
            rules_orgnl.append(rules[i])
    rules_orgnl.append(rules[-1])

    with open('%s' % (sys.argv[1] + '_orgnl'), 'w') as fo:
        for r in rules_orgnl:
            fo.write('%s\n' % r)

    with open('%s' % (sys.argv[1] + '_updt'), 'w') as fo:
        for r in rules_updt:
            fo.write('%s\n' % r)

if __name__ == "__main__":
    main()
