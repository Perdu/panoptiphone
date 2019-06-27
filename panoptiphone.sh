#!/bin/bash

if [ "$#" -eq 1 ]
then
    iface="$1"
else
    iface="wlan0"
fi

is_monitor=$(iwconfig "$iface" | grep -c Monitor)

if [ "$is_monitor" -eq 0 ]
then
    echo "Switching $iface to monitor mode"
    sudo ifconfig "$iface" down && sudo iwconfig "$iface" mode monitor && sudo ifconfig "$iface" up
fi

tshark -V -i "$iface" -l -Y "wlan.fc.type_subtype == 0x4 && not _ws.malformed && radiotap.dbm_antsignal > -60" -T pdml -E separator=";" -E quote=d | python2 -u panoptiphone.py -ig
