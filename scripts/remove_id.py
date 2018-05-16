#! /usr/bin/python

import sys

def main():
    traces = []

    with open('%s' % sys.argv[1]) as fi:
        for i in fi.readlines():
            traces.append(i)

    with open('%s' % sys.argv[1], 'w') as fo:
        for t in traces:
            ts = t.split(' ')
            new_t = ''
            for t in ts[:-1]:
                new_t = new_t + t + ' '
            new_t = new_t[:-1]
            fo.write('%s\n' % new_t)

if __name__ == '__main__':
    main()
