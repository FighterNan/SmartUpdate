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

def combine_then_smart_fullvolume(rule_set_path, update_rule_set_path, out_path, strategy, tolerate):
    # combine original set and updating set,
    # then apply smart_fullvolume_update
    combined_rule_set_path, traces_path = utils.generate_combined_trace(rule_set_path, update_rule_set_path, out_path)
    build_time, search_time = \
        smart_fullvolume_update.main(combined_rule_set_path, traces_path, combined_rule_set_path, strategy, tolerate, 3)
    return build_time, search_time

def hs_hs(rule_set_path, update_rule_set_path, out_path):
    # aplly hs in update_rule_set_path
    _, traces_path = utils.generate_combined_trace(rule_set_path, update_rule_set_path, out_path)
    _, search_time_origin = utils.hs_build(rule_set_path, traces_path)
    update_time, search_time_new = utils.hs_build(update_rule_set_path, traces_path)
    total_search_time = search_time_origin+search_time_new
    return update_time, total_search_time

def hs_tss(rule_set_path, update_rule_set_path, out_path):
    # aplly tss in update_rule_set_path
    _, traces_path = utils.generate_combined_trace(rule_set_path, update_rule_set_path, out_path)
    subset_full_name = utils.range2prefix(update_rule_set_path, update_rule_set_path)
    _, search_time_origin = utils.hs_build(rule_set_path, traces_path)
    update_time, search_time_new = utils.tss_build(subset_full_name, traces_path)
    total_search_time = search_time_origin + search_time_new
    return update_time, total_search_time

def build_another_smart_fullvolume(rule_set_path, update_rule_set_path, out_path, strategy, tolerate):
    # aplly smart-update in update_rule_set_path
    _, traces_path = utils.generate_combined_trace(rule_set_path, update_rule_set_path, out_path)
    _, search_time_origin = utils.hs_build(rule_set_path, traces_path)
    update_time, search_time_new = \
        smart_fullvolume_update.main(update_rule_set_path, traces_path, out_path, strategy, tolerate, 3)
    total_search_time = search_time_origin+search_time_new
    return update_time, total_search_time

def update_speed_first(rule_set_path, update_rule_set_path, out_path):
    update_time, search_time = hs_tss(rule_set_path, update_rule_set_path, out_path)
    return update_time, search_time

def classify_speed_first(rule_set_path, update_rule_set_path, out_path):
    update_time, search_time = combine_then_smart_fullvolume(rule_set_path, update_rule_set_path, out_path, 1, 1e6)
    return update_time, search_time

def hybrid(rule_set_path, update_rule_set_path, out_path):
    update_rule_set = utils.load_rule_set(update_rule_set_path)
    if len(update_rule_set)<5000:
        update_time, search_time = hs_hs(rule_set_path, update_rule_set_path, out_path)
    else:
        update_time, search_time = build_another_smart_fullvolume(rule_set_path, update_rule_set_path, out_path, 1, 1e6)
    return update_time, search_time

def main(rule_set_path, update_rule_set_path, out_path, strategy):
    if strategy==1:
        print("classify_speed_first")
        update_time, search_time = classify_speed_first(rule_set_path, update_rule_set_path, out_path)
    elif strategy==2:
        print("hybrid")
        update_time, search_time = hybrid(rule_set_path, update_rule_set_path, out_path)
    else:
        print("update_speed_first")
        update_time, search_time = update_speed_first(rule_set_path, update_rule_set_path, out_path)
    return update_time, search_time

if __name__ == "__main__":
    # ../test/rules/ipc1_10K ../test/my_rules/my_ipc1_10K group_sets/ -s 2
    parser = argparse.ArgumentParser()
    parser.add_argument("rule_set_path", type=str, help="name of original rule set")
    parser.add_argument("update_rule_set_path", type=str, help="original name of rule set")
    parser.add_argument("out_path", type=str, help="output path for rules after grouping")
    parser.add_argument("-s", "--strategy", type=int, help="choose the strategy of SmartUpdate", default=1)
    args = parser.parse_args()

    update_time, search_time = main(args.rule_set_path, args.update_rule_set_path, args.out_path, args.strategy)
    print("SmartUpdate update time:%s" % update_time)
    print("Search time:%s" % search_time)