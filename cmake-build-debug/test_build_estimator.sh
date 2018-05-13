#!/usr/bin/env bash

algo=1
path_prefix="../test/p_rules/"
rule_sets=("acl1" "acl1_100" "acl1_1k" "acl1_10k"
           "fw1" "fw1_100" "fw1_1k" "fw1_10k" "fw1"
           "ipc1" "ipc1_100" "ipc1_1k" "ipc1_10k")

for rule_set in ${rule_sets[@]}; do
    ./SmartUpdate -a ${algo} -r ${path_prefix}${rule_set} -e 1
done