#! /usr/bin/python

# -*- coding: utf-8 -*-
"""
    Description : test update speed and classification speed
    Author      : Nan Zhou
    Date        : May 27, 2018
"""
import subprocess
import utils
import argparse
import confs


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("rule_set_name", type=str, help="name of original rule set")
    parser.add_argument("update_rule_set_name", type=str, help="original name of rule set")
    parser.add_argument("out_path", type=str, help="output path for rules after grouping")
    args = parser.parse_args()

    # update_time, search_time, packet_num = utils.hs_update(confs.range_rules_path + args.rule_set_name, confs.update_range_rules_path + args.update_rule_set_name, args.out_path)


    update_time, search_time, packet_num = utils.tss_update(args.rule_set_name, args.update_rule_set_name, args.out_path)
    print("Update time:%s" % update_time)
    print("Search time:%s" % search_time)
    print("Packet num:%s" % packet_num)