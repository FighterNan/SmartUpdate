#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Description : range rules to prefix rules
    Author      : Nan Zhou
    Date        : May 17, 2018
"""
import argparse

def prefix2range(prefix, length, W):
    ret = {}
    ret['begin'] = prefix
    ret['end'] = prefix + (1 << (W - length)) - 1
    return ret


def range2prefix(begin, end, W):
    p = {
        'address': [],
        'mask': []
    }
    while begin <= end:
        i = 1
        while i <= W:
            if begin % (1 << i) != 0 or begin + (1 << i) - 1 > end:
                break;
            i += 1
        p['address'].append(begin)
        p['mask'].append(W - i + 1)
        begin += 1 << (i - 1)
    return p


def main(ruleset, outpath):
    r = {
        'begin': 0,
        'end': 0
    }
    W = 16

    traces = []
    with open('%s' % ruleset) as fi:
        for i in fi.readlines():
            traces.append(i)

    with open('%s' % outpath ,'w') as fo:
        for j in range(0, len(traces)):
            flow = traces[j].split(' ')
            r['begin'] = int(flow[2])
            r['end'] = int(flow[4])
            src_ports = range2prefix(r['begin'], r['end'], W)
            r['begin'] = int(flow[5])
            r['end'] = int(flow[7])
            dst_ports = range2prefix(r['begin'], r['end'], W)
            for a in range(0, len(src_ports['address'])):
                for b in range(0, len(dst_ports['address'])):
                    if len(flow) is 10:
                        fo.write('%s %s %s/%s %s/%s %s %s\n' % (
                            flow[0], flow[1], src_ports['address'][a], src_ports['mask'][a],
                            dst_ports['address'][b], dst_ports['mask'][b], flow[8], flow[9][:-1]))
                    else:
                        fo.write('%s %s %s/%s %s/%s %s %s\n' % (
                            flow[0], flow[1], src_ports['address'][a], src_ports['mask'][a],
                            dst_ports['address'][b], dst_ports['mask'][b], flow[8][:-1], str(j+1)))

    if len(traces[0].split(' ')) is 9:
        with open('%s' % ruleset, 'w') as fo:
            for j in range(0, len(traces)):
                fo.write('%s\n' % (traces[j][:-1] + ' ' + str(j+1)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ruleset", type=str, help="original name of rule set")
    parser.add_argument("outpath", type=str, help="original name of rule set")
    args = parser.parse_args()

    main(args.ruleset, args.outpath)
