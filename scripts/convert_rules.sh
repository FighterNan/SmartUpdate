# /bin/bash

declare -a files=("acl1" "acl1_100" "acl1_1K" "acl1_10K" "fw1" "fw1_100" "fw1_1K" "fw1_10K" "ipc1" "ipc1_100" "ipc1_1K" "ipc1_10K")

for file in "${files[@]}"; do
    #echo ${file##*/}
    echo $file
    ./split_rules.py ../test/rules/$file
    ./rule2prefix.py ../test/rules/$file ../test/p_rules/$file
    ./rule2prefix.py ../test/rules/${file}_orgnl ../test/p_rules/${file}_orgnl
    ./rule2prefix.py ../test/rules/${file}_updt ../test/p_rules/${file}_updt
    #./rule2prefix.py $file ../test/p_rules/${file##*/}
done
