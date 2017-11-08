#!/bin/bash

# cuts the pcap file into small file so that generated xml file are not too huge
# Not really needed anymore since I parse all XML files as streams now

for file in "$@"
do
    pcap=$(basename "$file")
    mkdir /tmp/parse_pcap/
    editcap -c 1000 "$file" /tmp/parse_pcap/"$pcap"
    for f in /tmp/parse_pcap/*
    do
	python panoptiphone.py -xf <(tshark -r "$f" -T pdml)
    done
    rm -rf /tmp/parse_pcap/
done
