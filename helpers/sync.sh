#!/bin/bash
# this will sync the cloudstack modules in a repo located under this repo

cp ../ansible-modules-extras/cloud/cloudstack/cs_*.py .
str='from ansible.module_utils.cloudstack import *'
for i in $(ls cs_*.py); do
    sed -i -e "/$str/r ansible_cloudstack_utils.py"  -e "/$str/d" $i
done
