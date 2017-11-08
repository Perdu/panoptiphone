Panoptiphone
=============

Panoptiphone is a tool inspired by the web browser fingerprinting tool Panopticlick, which aims to show the identifying information that can be found in the frames broadcast by a Wi-Fi-enabled device. Information is passively collected from devices that have their Wi-Fi interface enabled, even if they are not connected to an access point. Panoptiphone uses this information to create a fingerprint of the device and empirically evaluate its uniqueness among a database of fingerprints. The user is then shown how much identifying information its device is leaking through Wi-Fi and how unique it is.

See details in the related paper: "Panoptiphone: How Unique is Your Wi-Fi Device?" https://hal.inria.fr/hal-01330479/file/paper.pdf


## Dependencies ##

tshark
python-tk
python-matplotlib

## Install ##

Rename config.py.example config.py, and replace CHANGEME with a random key (chose a long and random password, you won't need to remember it).

## Usage ##

