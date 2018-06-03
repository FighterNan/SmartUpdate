# PCVisor

## folder structure

* [`build/`](https://github.com/FighterNan/SmartUpdate/tree/master/build) - store the built staff
* [`code/`](https://github.com/FighterNan/SmartUpdate/tree/master/code) - c source codes 
* [`scripts/`](https://github.com/FighterNan/SmartUpdate/tree/master/scripts) - scripts of SmartUpdate 

## how to run

``` Bash
# how to build 
mkdir build
cd build
cmake ..
make 

# how to run c codes
# HyperSplit
./build/SmartUpdate -a 0 -e 1 -r test/rules/fw1_10K -t test/traces/fw1_10K_trace
# TSS
./build/SmartUpdate -a 1 -e 1 -r test/p_rules/fw1_10K -t test/traces/fw1_10K_trace

# how to run python codes
python python some_script.py -h
```
