#! /usr/bin/python

# -*- coding: utf-8 -*-
"""
    Description : Smart Update, incremental
    Author      : Nan Zhou
    Date        : May 27, 2018
"""

from __future__ import division
import argparse
import subprocess
import group
import utils
import confs
import smart_fullvolume_update


def smart_fullvolume(rule_set_path, update_rule_set_path, out_path, strategy, tolerate):
    # combine original set and updating set,
    # then apply smart_fullvolume_update
    combined_rule_set_path, traces_path = utils.generate_combined_trace(rule_set_path, update_rule_set_path, out_path)
    build_time, search_time = \
        smart_fullvolume_update.main(combined_rule_set_path, traces_path, combined_rule_set_path, strategy, tolerate)
    print("SmartUpdate update time:%s" % build_time)
    print("Search time:%s" % search_time)

def hs_naive_group(rule_set_path, update_rule_set_path, out_path):
    # aplly hs in update_rule_set_path
    _, traces_path = utils.generate_combined_trace(rule_set_path, update_rule_set_path, out_path)
    _, search_time_origin = utils.hs_build(rule_set_path, traces_path)
    update_time, search_time_new = utils.hs_build(update_rule_set_path, traces_path)
    total_search_time = search_time_origin+search_time_new

    print("SmartUpdate update time:%s" % update_time)
    print("Search time:%s" % total_search_time)

def hs_smart_group(rule_set_path, update_rule_set_path, out_path, strategy, tolerate):
    # aplly hs in update_rule_set_path
    _, traces_path = utils.generate_combined_trace(rule_set_path, update_rule_set_path, out_path)
    _, search_time_origin = \
        smart_fullvolume_update.main(rule_set_path, traces_path, out_path, strategy, tolerate)
    update_time, search_time_new = \
        smart_fullvolume_update.main(update_rule_set_path, traces_path, out_path, strategy, tolerate)
    total_search_time = search_time_origin+search_time_new

    print("SmartUpdate update time:%s" % update_time)
    print("Search time:%s" % total_search_time)

def classify_speed_first(rule_set, traces, out_path):
    # firstly, it will divide the ruleset to four subsets
    # will apply hs in each subset
    stepped_thresh = 0.1
    subsets = group.group_by_category(rule_set, stepped_thresh)
    group.output_rule_sets(subsets, out_path)

    infos = []
    total_build_time = 0
    total_search_time = 0
    for subset_name in subsets.keys():
        info = {}
        subset_full_name = out_path+"_"+subset_name
        return_strs = subprocess.getoutput("./" + confs.SMART_UPDATE + " -a -0" + " -e 1" + " -r " + subset_full_name + \
                                           " -t " + traces)
        build_time = utils.get_info("Time for building(us):", return_strs.split('\n'))
        search_time = utils.get_info("Time for searching(us):", return_strs.split('\n'))
        total_build_time+=float(build_time)
        total_search_time+=float(search_time)
        info["build_"+subset_name] = build_time
        info["search_"+subset_name] = search_time
        infos.append(info)
    print(infos)
    print("SmartUpdate build time:%s" % total_build_time)
    print("Search time:%s" % total_search_time)


def update_speed_first(rule_set, traces, out_path):
    # firstly, it will divide the ruleset to four subsets
    # will apply hs in ll and ss; apply tss in ls and sl
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
            subset_full_name = utils.range2prefix(subset_full_name)
            return_strs = subprocess.getoutput("./" + confs.SMART_UPDATE + " -a 1" + " -e 1" + " -r " + subset_full_name + \
                                               " -t " + traces)
        else:
            return_strs = subprocess.getoutput("./" + confs.SMART_UPDATE + " -a -0" + " -e 1" + " -r " + subset_full_name + \
                                               " -t " + traces)
        build_time = utils.get_info("Time for building(us):", return_strs.split('\n'))
        search_time = utils.get_info("Time for searching(us):", return_strs.split('\n'))
        total_build_time += float(build_time)
        total_search_time += float(search_time)
        info["build_" + subset_name] = build_time
        info["search_" + subset_name] = search_time
        infos.append(info)
    print(infos)
    print("SmartUpdate build time:%s" % total_build_time)
    print("Search time:%s" % total_search_time)


def main(rule_set_path, update_rule_set_path, out_path, strategy, tolerate):
    print("smart_fullvolume")
    smart_fullvolume(rule_set_path, update_rule_set_path, out_path, strategy, tolerate)
    print("hs_naive_group")
    hs_naive_group(rule_set_path, update_rule_set_path, out_path)
    print("hs_smart_group")
    hs_naive_group(rule_set_path, update_rule_set_path, out_path)




if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    # exp: ../test/rules/fw1_10K ../test/my_rules/my_fw1_1K group_sets/fw1_10K -s 1
    parser.add_argument("rule_set_path", type=str, help="name of original rule set")
    parser.add_argument("update_rule_set_path", type=str, help="original name of rule set")
    parser.add_argument("out_path", type=str, help="output path for rules after grouping")
    parser.add_argument("-s", "--strategy", type=int, help="choose the strategy of SmartUpdate", default=1)
    parser.add_argument("-t", "--tolerate", type=int, help="tolerable time for incremental updating (us)", default=5*1e6)
    args = parser.parse_args()

    main(args.rule_set_path, args.update_rule_set_path, args.out_path, args.strategy, args.tolerate)
