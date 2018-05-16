#!/bin/bash

type="my_ipc1_"
path="../test/my_rules/"
names=("100" "300" "500" "700" "900" "1k" "3k" "5k" "9k" "10k" "20k" "30k" "40k" "50k" "60k" "70k" "80k" "90k" "100k")
for name in ${names[@]}; do
    echo ${path}${type}${name}
    python add_id.py ${path}${type}${name}
done
