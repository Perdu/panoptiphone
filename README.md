Panoptiphone
=============

Panoptiphone is a tool inspired by the web browser fingerprinting tool Panopticlick, which aims to show the identifying information that can be found in the frames broadcast by a Wi-Fi-enabled device. Information is passively collected from devices that have their Wi-Fi interface enabled, even if they are not connected to an access point. Panoptiphone uses this information to create a fingerprint of the device and empirically evaluate its uniqueness among a database of fingerprints. The user is then shown how much identifying information its device is leaking through Wi-Fi and how unique it is.

See details in the related paper: [Panoptiphone: How Unique is Your Wi-Fi Device?](https://hal.inria.fr/hal-01330479/file/paper.pdf). Information elements fingerprinting were introduced in our other paper [Why MAC address randomization is not enough: An analysis of Wi-Fi network discovery mechanisms](https://hal.inria.fr/hal-01282900/document).

## Dependencies ##

- tshark
- python-tk
- python-matplotlib

## Install ##

Rename config.py.example config.py, and replace CHANGEME with a random key (chose a long and random password, you won't need to remember it).

All calculation is made relatively to a database. You can chose to iteratively build a database out of devices you encounter, or create a database out of public datasets. For instance, you can download the [Sapienza dataset](https://crawdad.org/sapienza/probe-requests/20130910/) add all devices using the following command (expect a few hours):
```
for i in sapienza/*/*.pcap* ; do echo "$i" ; tshark -r "$i" -T pdml | python panoptiphone.py >/dev/null ; done
```

## Usage ##

Several scripts constitute the program:
- panoptiphone.py makes the core calculation and can be launched with several options (described below).
- panoptiphone.sh is a script to launch previous program with the correct options to operate live on the wlan0 interface (wlan0 must be able to switch to monitor mode).
- panoptiphone_file.sh launches previous program on a file given as a parameter.

panoptiphone's.py options:
- -d: dump the database's content, i.e., information about the different fields (information elements) and the identifying information they bring
- -g: activate graphical interface
- -i: activate interactive mode (displays all incoming device captures)
- -v <field>: dump details about a field

## Examples of uses ##

- CLI

```
$ ./panoptiphone.sh wlan0 # Live capture
Capturing on ’wlan0’
MAC address: c0:ee:fb:75:0d:59 (OnePlus Tech (Shenzhen) Ltd)
One in 13654.92 devices share this signature
Field                             | Entropy | One in x devices have this value | value
wps.uuid_e                        |  0.528  |                         5606.000 |
wlan_mgt.tag.number               |  0.483  |                       163812.000 | 0,1,50,3,45,221,127
wlan_mgt.supported_rates          |  0.304  |                       163793.000 | 2,4,11,22
wlan_mgt.extended_supported_rates |  0.302  |                       162962.000 | 12,18,24,36,48,72,96,108
wlan_mgt.ht.capabilities.psmp     |  0.301  |                       162962.000 | 0x0000012c
wlan_mgt.ht.ampduparam            |  0.000  |                            1.000 | 0x00000003
[...]
total                             |  3.489  |
```

```
$ python panoptiphone.py -d # dump database
163858 devices in the database
Information element | Entropy | Aff dev | Number of values
wlan_mgt.tag.length |   3.959 |  99.97  |  417
wlan_mgt.tag.number |   3.046 |  99.97  |  414
wlan_mgt.ssid       |   3.695 |  99.97  |  20592
[...]
total               |   5.834 |    -    |  163858
29171 devices (17.80%) are unique in the database
```

```
$ python panoptiphone.py -v wlan_mgt.txbf.txbf # list possible values of a field
Value     | Number of times seen
0;0       | 115512
0         | 17353
FFFFFFFF  | 4
```

- CLI and GUI: Left-hand size of the image show the output on the terminal, listing the different fields, the entropy they bring (how much identifying information they bring), and the uniqueness of the value. Right-hand size is the GUI: detected devices are listed on the left, identified by their MAC address and their constructor name. Once one is selected, a dendrogram displays how much entropy is brought by each field and subfield.

![GUI example](example.png?raw=true "GUI example")



[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.1044394.svg)](https://doi.org/10.5281/zenodo.1044394)

