#!/bin/bash

file="$1"

tshark -V -r "$file" -l -Y "wlan.fc.type_subtype == 0x4 && not _ws.malformed" -T fields -e frame.time -e wlan.sa -e wlan.seq -e wlan_mgt.ssid -e wps.uuid_e -e wlan_mgt.tag.number -e wlan_mgt.supported_rates -e wlan_mgt.extended_supported_rates -e wlan_mgt.ht.capabilities -e wlan_mgt.ht.ampduparam -e wlan_mgt.ht.mcsset.rxbitmask -e wlan_mgt.htex.capabilities -e wlan_mgt.txbf -e wlan_mgt.asel -e wlan_mgt.extcap -e wlan_mgt.interworking.access_network_type -e radiotap.dbm_antsignal -E separator=";" -E quote=d | python -u panoptiphone.py
