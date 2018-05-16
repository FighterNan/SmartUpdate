#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Description : add id to rulesets
    Author      : Nan Zhou
    Date        : May 11, 2018
"""

import argparse

def main(fname):
    traces = []
    with open(fname, 'r') as fin:
        i = 1
        for line in fin:
            traces.append(line[0:-1]+" "+str(i))
            i += 1
    with open(fname, 'w') as fout:
        for line in traces:
            print(line, file=fout)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=str, help="file name")
    args = parser.parse_args()

    main(args.file)
