#! /usr/bin/python

# -*- coding: utf-8 -*-
"""
    Description : Group Rules
    Author      : Nan Zhou
    Date        : May 14, 2018
"""

from __future__ import division
import IPy
import argparse


def main(ruleset, out_path):
    ss = []
    ls_sl = []
    ll = []

    fullRange = IPy.IP("255.255.255.255").int()
    thresh = 0.1

    with open(ruleset, 'r') as fin:
        listRules = fin.readlines()
        for strRule in listRules:
            if strRule is None:
                continue
            strRule = strRule.replace('@','')
            strs = strRule.split(' ')

            srcIP = strs[0]
            srcIP = IPy.IP(srcIP).strNormal(3).split('-')
            srcIPStart = srcIP[0]
            if len(srcIP) == 1:
                srcIPRange = 1 # xxx.xxx.xxx.xxx/32
            else:
                srcIPEnd = srcIP[1]
                srcIPRange = IPy.IP(srcIPEnd).int()-IPy.IP(srcIPStart).int()

            dstIP = strs[1]
            dstIP = IPy.IP(dstIP).strNormal(3).split('-')
            dstIPStart = dstIP[0]
            if len(dstIP) == 1:
                dstIPRange = 1
            else:
                dstIPEnd = dstIP[1]
                dstIPRange = IPy.IP(srcIPEnd).int()-IPy.IP(srcIPStart).int()

            if ((srcIPRange / fullRange) < thresh and (dstIPRange / fullRange) < thresh):
                ss.append(strRule)
            elif ((srcIPRange / fullRange) > thresh and (dstIPRange / fullRange) > thresh):
                ll.append(strRule)
            else:
                ls_sl.append(strRule)
    print("ss: %s; ls_sl: %s; ll: %s" % (len(ss), len(ls_sl), len(ll)))
    with open(out_path+ "_ss", 'w') as fout_ss, \
         open(out_path+ "_lssl", 'w') as fout_slls, \
         open(out_path+ "_ll", 'w') as fout_ll:
        for str in ss:
            fout_ss.write("@"+str)
        for str in ls_sl:
            fout_slls.write("@"+str)
        for str in ll:
            fout_ll.write("@"+str)


    if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("ruleset", type=str, help="original ruleset path")
        parser.add_argument("outpath", type=str, help="output ruleset path after grouping")
        args = parser.parse_args()

        main(args.ruleset, args.outpath)