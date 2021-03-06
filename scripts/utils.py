#! /usr/bin/python

# -*- coding: utf-8 -*-
"""
    Description : useful functions
    Author      : Nan Zhou
    Date        : May 18, 2018
"""
import subprocess
import confs
import shlex

# format metric_name:number
def get_info(str_prefix, output_str_list):
    number = None
    for output_str in output_str_list:
        if output_str.startswith(str_prefix):
            temp_str = output_str.replace(str_prefix,"")
            number = temp_str.strip(" ")
    if number is not None:
        return float(number)
    else:
        return 0

def load_rule_set(rule_set_path):
    with open(rule_set_path, 'r') as fin:
        rules_list = fin.readlines()
    return rules_list

def range2prefix(rule_set_path, output_path):
    os_command("python " + confs.RANGE_TO_PREFIX + " "+ output_path + " "+rule_set_path+"_p")
    return (rule_set_path+"_p")

def remove_id(rule_set_path, output_path):
    rule_set_name = rule_set_path.split("/")
    rule_set_name = rule_set_name[len(rule_set_name)-1]
    os_command("python " + confs.REMOVE_ID + " " + rule_set_path +" "+output_path+rule_set_name)
    return (output_path+rule_set_name)

def add_id(rule_set_path):
    os_command("python " + confs.ADD_ID + " " + rule_set_path)
    return rule_set_path

def combine_rule_sets(rule_set_path_list):
    rule_set_combined = rule_set_path_list[0]+"_updated"
    with open(rule_set_combined, 'w') as fout:
        for i in range(0, len(rule_set_path_list)):
            rules = []
            with open(rule_set_path_list[i], 'r') as fin:
                for i in fin.readlines():
                    rules.append(i)
            for rule in rules:
                fout.write('%s' % rule)
    for rule_set_path in rule_set_path_list:
        os_command("rm "+rule_set_path)
    return rule_set_combined

def generate_traces(rule_set_path):
    os_command("./" + confs.TRACE_GENERATOR + " 1 0 10 " + rule_set_path)
    return rule_set_path+"_trace"

def generate_combined_trace(rule_set_path, update_rule_set_path, out_prefix):
    rule_set_path_temp = remove_id(rule_set_path, out_prefix)
    update_rule_set_path_temp = remove_id(update_rule_set_path, out_prefix)
    updated_rule_set = combine_rule_sets([rule_set_path_temp, update_rule_set_path_temp])
    traces_path = generate_traces(updated_rule_set)
    add_id(updated_rule_set)
    return updated_rule_set, traces_path


def hs_build(rule_set_path, traces_path):
    return_strs = os_command("./" + confs.SMART_UPDATE + " -a 0" + " -r " + rule_set_path + \
                                       " -t " + traces_path)
    build_time = get_info("Time for building(us):", return_strs.split('\n'))
    search_time = get_info("Time for searching(us):", return_strs.split('\n'))
    return build_time, search_time

def tss_build(rule_set_path, traces_path):
    return_strs = os_command("./" + confs.SMART_UPDATE + " -a 1" + " -r " + rule_set_path + \
                                       " -t " + traces_path)
    build_time = get_info("Time for building(us):", return_strs.split('\n'))
    search_time = get_info("Time for searching(us):", return_strs.split('\n'))
    return build_time, search_time

def hs_build_estimator(rule_set_path):
    return_strs = os_command("./" + confs.SMART_UPDATE + " -a 0" + " -e 1" + " -r " + rule_set_path + " -s 1")
    build_time = get_info("Estimated time:", return_strs.split('\n'))
    return build_time

def hs_update(rule_set_path, update_rule_set_path, out_prefix):
    _, traces_path = generate_combined_trace(rule_set_path, update_rule_set_path, out_prefix)
    return_strs = os_command("./" + confs.SMART_UPDATE + " -a 0" + " -r " + rule_set_path + " -u " + update_rule_set_path+ \
                                       " -t " + traces_path + " -s "+" 2")
    update_time = get_info("Time for updating(us):", return_strs.split('\n'))
    search_time = get_info("Time for searching(us):", return_strs.split('\n'))
    packets_num = get_info("Packets loaded:", return_strs.split('\n'))
    return update_time, search_time, packets_num

def tss_update(rule_set_name, update_rule_set_name, out_prefix):
    _, traces_path = generate_combined_trace(confs.RANGE_RULES_PATH + rule_set_name, confs.UPDATE_RANGE_RULES_PATH + update_rule_set_name, out_prefix)
    return_strs = os_command("./" + confs.SMART_UPDATE + " -a 1" + " -r " + confs.PRFX_RULES_PATH + rule_set_name + " -u " + confs.UPDATE_PREFX_RULES_PATH + update_rule_set_name + \
                                       " -t " + traces_path + " -s " +" 2")
    update_time = get_info("Time for updating(us):", return_strs.split('\n'))
    search_time = get_info("Time for searching(us):", return_strs.split('\n'))
    packets_num = get_info("Packets loaded:", return_strs.split('\n'))
    return update_time, search_time, packets_num

def os_command(cmd):
    args = shlex.split(cmd)
    process = subprocess.Popen(args, stdout=subprocess.PIPE)
    return_strs, _ = process.communicate()
    return_strs = str(return_strs, encoding="utf8")
    return return_strs

if __name__ == "__main__":
    str = "Time for updating(us): 1388"
    print(get_info("Time for updating(us):", [str]))
