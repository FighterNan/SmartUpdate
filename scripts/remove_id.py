#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Description : remove id to rulesets
    Author      : Nan Zhou
    Date        : May 17, 2018
"""

import argparse

def main(fname):
    traces = []

    with open(fname, 'r') as fin:
        for i in fin.readlines():
            traces.append(i)

    with open(fname, 'w') as fout:
        for t in traces:
            ts = t.split(' ')
            new_t = ''
            for t in ts[:-1]:
                new_t = new_t + t + ' '
            new_t = new_t[:-1]
            fout.write('%s\n' % new_t)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="file name")
    args = parser.parse_args()

    main(args.file)
