#!/usr/bin/env bash
origin_ruleset="acl1_10K"
type="my_acl1_"
file_names=("100" "500" "1k" "5k" "7k" "10k")

update_path_prefix="../test/my_rules/"
path_prefix="../test/rules/"
output_prefix="group_sets/"

for file_name in ${file_names[@]}; do
    echo ${origin_ruleset}_add_${type}${file_name}
    python test_update_time.py ${origin_ruleset} ${type}${file_name} ${output_prefix}
done