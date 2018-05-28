#! /usr/bin/python

# -*- coding: utf-8 -*-
"""
    Description : Smart Update, full-volume
    Author      : Nan Zhou
    Date        : May 14, 2018
"""

from __future__ import division
import argparse
import subprocess
import group
import utils
import confs
import shlex

def classify_speed_first(rule_set, traces_path, out_path):
    # firstly, it will divide the ruleset to four subsets
    # will apply hs in each subset
    # rule_set here is a list
    stepped_thresh = 0.1
    subsets = group.group_by_category(rule_set, stepped_thresh)
    group.output_rule_sets(subsets, out_path)

    infos = []
    total_build_time = 0
    total_search_time = 0
    for subset_name in subsets.keys():
        info = {}
        subset_full_name = out_path+"_"+subset_name
        return_strs = utils.os_command("./" + confs.SMART_UPDATE + " -a 0" + " -r " + subset_full_name + \
                                           " -t " + traces_path)
        build_time = utils.get_info("Time for building(us):", return_strs.split('\n'))
        search_time = utils.get_info("Time for searching(us):", return_strs.split('\n'))
        total_build_time+=float(build_time)
        total_search_time+=float(search_time)
        info["build_"+subset_name] = build_time
        info["search_"+subset_name] = search_time
        infos.append(info)
    print(infos)
    return total_build_time, total_search_time

def update_speed_first(rule_set, traces_path, out_path):
    # firstly, it will divide the ruleset to four subsets
    # will apply hs in ll and ss; apply tss in ls and sl
    # rule_set here is a list
    stepped_thresh = 0.1
    subsets = group.group_by_category(rule_set, stepped_thresh)
    group.output_rule_sets(subsets, out_path)
    infos = []
    total_build_time = 0
    total_search_time = 0
    for subset_name in subsets.keys():
        info = {}
        subset_full_name = out_path+"_"+subset_name
        subset_full_name = utils.range2prefix(subset_full_name, subset_full_name)
        return_strs = utils.os_command("./" + confs.SMART_UPDATE + " -a 1" + " -r " + subset_full_name + \
                                               " -t " + traces_path)
        build_time = utils.get_info("Time for building(us):", return_strs.split('\n'))
        search_time = utils.get_info("Time for searching(us):", return_strs.split('\n'))
        total_build_time += float(build_time)
        total_search_time += float(search_time)
        info["build_" + subset_name] = build_time
        info["search_" + subset_name] = search_time
        infos.append(info)
    print(infos)
    return total_build_time, total_search_time

def hybrid(rule_set, traces_path, out_path):
    # firstly, it will divide the ruleset to four subsets
    # will apply hs in ll and ss; apply tss in ls and sl
    # rule_set here is a list
    stepped_thresh = 0.1
    subsets = group.group_by_category(rule_set, stepped_thresh)
    group.output_rule_sets(subsets, out_path)
    infos = []
    total_build_time = 0
    total_search_time = 0
    for subset_name in subsets.keys():
        info = {}
        subset_full_name = out_path+"_"+subset_name
        if (subset_name==confs.GROUP_NAME["small_large"] or subset_name==confs.GROUP_NAME["large_small"]):
            subset_full_name = utils.range2prefix(subset_full_name, subset_full_name)
            return_strs = utils.os_command("./" + confs.SMART_UPDATE + " -a 1" + " -r " + subset_full_name + \
                                               " -t " + traces_path)
        else:
            return_strs = utils.os_command("./" + confs.SMART_UPDATE + " -a 0" + " -r " + subset_full_name + \
                                               " -t " + traces_path)
        build_time = utils.get_info("Time for building(us):", return_strs.split('\n'))
        search_time = utils.get_info("Time for searching(us):", return_strs.split('\n'))
        total_build_time += float(build_time)
        total_search_time += float(search_time)
        info["build_" + subset_name] = build_time
        info["search_" + subset_name] = search_time
        infos.append(info)
    print(infos)
    return total_build_time, total_search_time


def main(rule_set_path, traces_path, out_path, strategy, tolerate):
    build_time = utils.hs_build_estimator(rule_set_path)
    print("Estimator: %s" % build_time)
    rule_set = utils.load_rule_set(rule_set_path)
    if (strategy==1 and build_time>tolerate):
        build_time, search_time = classify_speed_first(rule_set, traces_path, out_path)
    elif (strategy==2 and build_time>tolerate):
        build_time, search_time = hybrid(rule_set, traces_path, out_path)
    elif (strategy == 3 and build_time > tolerate):
        build_time, search_time = update_speed_first(rule_set, traces_path, out_path)
    else:
        build_time, search_time = utils.hs_build(rule_set_path, traces_path)
    return build_time, search_time

if __name__ == "__main__":
    # exp: ../test/rules/fw1_10K ../test/traces/fw1_10K_trace group_sets/fw1_10K -s 1
    parser = argparse.ArgumentParser()
    parser.add_argument("rule_set_path", type=str, help="name of original rule set")
    parser.add_argument("traces", type=str, help="traces to do packet classification")
    parser.add_argument("out_path", type=str, help="output path for rules after grouping")
    parser.add_argument("-s", "--strategy", type=int, help="choose the strategy of SmartUpdate", default=1)
    parser.add_argument("-t", "--tolerate", type=int, help="tolerable time for full-volume updating (us)", default=5*1e6)
    args = parser.parse_args()

    build_time, search_time = main(args.rule_set_path, args.traces, args.out_path, args.strategy, args.tolerate)

    print("SmartUpdate build time:%s" % build_time)
    print("Search time:%s" % search_time)