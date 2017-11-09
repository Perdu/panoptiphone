#!/bin/bash

file="$1"

for i in "$@"
do
    echo "$i"
    tshark -r "$i" -T pdml | python panoptiphone.py -xg
done
