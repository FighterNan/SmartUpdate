#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Description : remove id to rulesets
    Author      : Nan Zhou
    Date        : May 17, 2018
"""

import argparse

def main(input_fname, output_fname):
    traces = []

    with open(input_fname, 'r') as fin:
        for i in fin.readlines():
            traces.append(i)

    with open(output_fname, 'w') as fout:
        for t in traces:
            ts = t.split(' ')
            new_t = ''
            for t in ts[:-1]:
                new_t = new_t + t + ' '
            new_t = new_t[:-1]
            fout.write('%s\n' % new_t)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=str, help="input file with id")
    parser.add_argument("output", type=str, help="output file without id")
    args = parser.parse_args()

    main(args.input, args.output)
