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
import confs

full_range = IPy.IP("255.255.255.255").int()

category = {
    "ss":"ss",
    "sl":"sl",
    "ls":"ls",
    "ll":"ll"
}

def get_rule_cate(str_rule, thresh):
    str_rule = str_rule.replace('@', '')
    strs = str_rule.split(' ')

    src_ip = strs[0]
    src_ip = IPy.IP(src_ip).strNormal(3).split('-')
    src_ip_start = src_ip[0]
    if len(src_ip) == 1:
        src_ip_range = 1  # xxx.xxx.xxx.xxx/32
    else:
        src_ip_end = src_ip[1]
        src_ip_range = IPy.IP(src_ip_end).int() - IPy.IP(src_ip_start).int()

    dst_ip = strs[1]
    dst_ip = IPy.IP(dst_ip).strNormal(3).split('-')
    dst_ip_start = dst_ip[0]
    if len(dst_ip) == 1:
        dst_ip_range = 1
    else:
        dst_ip_end = dst_ip[1]
        dst_ip_range = IPy.IP(dst_ip_end).int() - IPy.IP(dst_ip_start).int()

    if ((src_ip_range / full_range) < thresh and (dst_ip_range / full_range) < thresh):
        return category["ss"]
    elif ((src_ip_range / full_range) > thresh and (dst_ip_range / full_range) > thresh):
        return category["ll"]
    elif ((src_ip_range / full_range) < thresh and (dst_ip_range / full_range) > thresh):
        return category["sl"]
    else:
        return category["ls"]

def group_once(ruleset, out_path, thresh):
    rules = {
        "ss":[],
        "sl":[],
        "ls":[],
        "ll":[]
    }

    with open(ruleset, 'r') as fin:
        rules_list = fin.readlines()
        for str_rule in rules_list:
            if str_rule is None:
                continue
            rules[get_rule_cate(str_rule, thresh)].append(str_rule)

    print("ss: %s; sl: %s; ls: %s; ll: %s" % (len(rules["ss"]), len(rules["sl"]), len(rules["ls"]), len(rules["ll"])))
    return rules

def output_rulesets(rules, out_path):
    with open(out_path+ "_"+ confs.GROUP_NAME["small_small"], 'w') as fout_ss, \
         open(out_path+ "_"+ confs.GROUP_NAME["small_large"], 'w') as fout_sl, \
         open(out_path+ "_"+ confs.GROUP_NAME["large_small"], 'w') as fout_ls, \
         open(out_path+ "_"+ confs.GROUP_NAME["large_large"], 'w') as fout_ll:

        if len(rules["ss"])>0:
            for str in rules["ss"]:
                fout_ss.write(str)
        if len(rules["sl"])>0:
            for str in rules["sl"]:
                fout_sl.write(str)
        if len(rules["ls"]) > 0:
            for str in rules["ls"]:
                fout_ls.write(str)
        if len(rules["ll"]) > 0:
            for str in rules["ll"]:
                fout_ll.write(str)

def main(ruleset, outpath):
    rulesets = group_once(ruleset, outpath, thresh=0.1)
    output_rulesets(rulesets, outpath)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("ruleset", type=str, help="original name of rule set")
    parser.add_argument("outpath", type=str, help="output name after grouping")
    args = parser.parse_args()

    main(args.ruleset, args.outpath)