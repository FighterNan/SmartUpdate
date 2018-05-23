#!/usr/bin/env bash

file_names=("acl1" "acl1_100" "acl1_1K"  "acl1_10K"  "fw1"  "fw1_100"  "fw1_1K"  "fw1_10K"  "ipc1"  "ipc1_100"  "ipc1_1K"  "ipc1_10K")
#  0:HyperSplit, 1:TSS
#  0:rules: HyperSplit 
#  1:prefix_rules: TSS
algo=1
ruleset_prefix="../test/p_rules/"
trace_prefix="../test/traces/"

for file_name in ${file_names[@]}; do
	echo alogrithm_${algo}_${file_name}
	./SmartUpdate -r ${ruleset_prefix}${file_name} -e 1 -a ${algo} -t ${trace_prefix}${file_name}_trace
done
