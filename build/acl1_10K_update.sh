#!/usr/bin/env bash

origin_ruleset="acl1_10K"
type="my_acl1_"
file_names=("100" "500" "1k" "5k" "7k" "10k")
#  0:HyperSplit, 1:TSS
#  0:rules: HyperSplit 
#  1:prefix_rules: TSS
algo=0
path_prefix="../test/rules/"
update_path_prefix="../test/my_rules/"

for file_name in ${file_names[@]}; do
	echo alogrithm_${algo}_${file_name}
	./SmartUpdate -r ${path_prefix}${origin_ruleset} -u ${update_path_prefix}${type}${file_name} -e 1 -a ${algo}
done
