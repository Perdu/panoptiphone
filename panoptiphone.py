#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import fileinput
import csv
import math
import pickle
import os
import signal
import datetime
import re
import StringIO
import getopt
import xml.etree.ElementTree
import threading
import time
from Tkinter import *
from matplotlib import pyplot as plt
from scipy.cluster.hierarchy import dendrogram, linkage
import numpy as np
import networkx as nx
import matplotlib
#matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
# implement the default mpl key bindings
#from matplotlib.backend_bases import key_press_handler
from matplotlib.figure import Figure
import hashlib
import json
from collections import OrderedDict
from config import sha256key


DB_FILE = 'database.db'
OUI_FILE = 'oui.txt'
MAX_TIME_DIFF_BURST = datetime.timedelta(0,0,100000)

db = {}
mac_addresses = []
totals = {}
OUIs = {}
last_frame_time = datetime.datetime(1970,1,1)
devices_seen_this_session = set()
gui = None
dendrograms = []
labels = []
str_ies = []
database_already_saved = False

class Options:
    f = sys.stdin
    interactive = False
    dump_db = False
    dump_values = False
    graphical = False
    write_file = None               # file object for writing JSON dumps of each flattened record; the resulting file is in .jl (JSON Lines) format

options = Options()

def convert_to_hashed_value(val):
    sha256 = hashlib.sha256()
    sha256.update(val)
    sha256.update(sha256key)
    return sha256.hexdigest()

def db_add(key, val):
    global db
    if key == 'wps.uuid_e':
        val = convert_to_hashed_value(val)
    if key in db:
        if val in db[key]:
            db[key][val] += 1
        else:
            db[key][val] = 1.0
    else:
        db[key] = {}
        db[key][val] = 1.0

def calculate_entropy(key, val):
    global db
    nb_devices = float(len(mac_addresses))
    if nb_devices == 0:
        nb_devices = 1
    if key == 'total':
        if val in totals:
            nb_seen = totals[val]
        else:
            nb_seen = 1
        frac = nb_seen/nb_devices
        return -math.log(frac, 2)
    else:
        if key == 'wps.uuid_e':
            val = convert_to_hashed_value(val)
        if key in db and val in db[key]:
            nb_seen = db[key][val]
        else:
            # this device was not added to the database
            nb_seen = 1
        frac = nb_seen/nb_devices
        return -frac * math.log(frac, 2)

def calculate_entropy_total(key):
    e = 0.0
    nb_devices = float(len(mac_addresses))
    if key == 'total':
        nb_devices_with_val = sum(totals.values())
        frac = (nb_devices - nb_devices_with_val)/nb_devices
        e = -frac * math.log(frac, 2)
    else:
        nb_devices_with_val = sum(db[key].values())
        frac = (nb_devices - nb_devices_with_val)/nb_devices
        for val in db[key]:
            e += calculate_entropy(key, val)
        if frac != 0:
            e += -frac * math.log(frac, 2)
    return e

def is_LA_bit_set(mac):
    first_byte = mac[0:2].decode("hex")
    return (ord(first_byte) & 0x02) != 0

def get_nb_spaces(val, max_val):
    nb_spaces = 0
    val = int(val)
    max_val = int(max_val)
    while len(str(val)) < len(str(max_val)):
        max_val = max_val / 10
        nb_spaces += 1
    return nb_spaces

def handle_elem(fields_xml, d, superfield, fields, seen_elems):
    nb_devices = len(mac_addresses)
    for field in fields_xml:
        subfields = field.findall('field')
        # Only use leaf nodes
        # Non-leaf nodes repeat values in the leaves
        name = field.get('name')
        if name == 'wlan.ssid' or name == 'wlan.ds.current_channel':
            fields_xml.remove(field)
            continue
        actual_name = name
        while name in seen_elems:
            name = name + " "
        seen_elems.add(name)
        d[superfield].append(name)
        d[name] = []
        if subfields != []:
            handle_elem(subfields, d, name, fields, seen_elems)
        else:
            fields[name] = {}
            val = field.get('value')
            if val == None:
                val = ''
            fields[name]['val'] = val
            fields[name]['entropy'] = calculate_entropy(actual_name, val)

def print_frame(f, mac_address):
    global totals
    global mac_addresses
    seen_elems = set()
    fields = {}
    d = {}
    fields_xml = f.findall("proto[@name='wlan']/*field")
    if fields_xml == []:
        # for some reason, there is no IE (malformed packet)
        return
    d["all"] = []
    handle_elem(fields_xml, d, "all", fields, seen_elems)
    cut_mac = mac_address[:8]
    if cut_mac in OUIs:
        vendor = OUIs[cut_mac]
    else:
        vendor = "unknown vendor"
    str_ie = get_str_ie(fields, mac_address, vendor)
    if mac_address not in devices_seen_this_session:
        str_ies.append(str_ie)
    if options.graphical:
        while (gui == None):
            print "waiting for graphical thread to start"
            time.sleep(0.1)
        if mac_address not in devices_seen_this_session:
            gui.lst_devices.add(mac_address, "(" + vendor + ")")
            create_dendrograms(d, fields)
    print
    print str_ie
    
    if options.write_file:
        dump_json(f, fields, mac_address, vendor)

def dump_json(frame, fields, mac_address, vendor):

    if not options.write_file: return
    dump = OrderedDict([('wlan.sa', mac_address), ('_vendor_', vendor)])
    
    dump['timestamp']   = frame.findall("proto[@name='geninfo']/field[@name='timestamp']")[0].get('value')
    dump['len']         = frame.findall("proto[@name='geninfo']/field[@name='len']")[0].get('show')
    dump['caplen']      = frame.findall("proto[@name='geninfo']/field[@name='caplen']")[0].get('show')
    
    dump['wlan.seq']    = frame.findall("proto[@name='wlan']/field[@name='wlan.seq']")[0].get('show')
    dump['wlan.ssid']   = list(filter(None, [f.get('show') for f in frame.findall("proto[@name='wlan']//field[@name='wlan.ssid']")]))

    # radiotap
    antsignal = sorted(int(f.get('show')) for f in frame.findall("proto[@name='radiotap']/field[@name='radiotap.dbm_antsignal']"))
    assert antsignal[-2] == antsignal[-1]
    dump['radiotap.dbm_antsignal'] = antsignal[:-1]
    
    # wlan_radio
    dump['wlan_radio.timestamp'] = frame.findall("proto[@name='wlan_radio']/field[@name='wlan_radio.timestamp']") [0].get('show')
    dump['wlan_radio.duration']  = frame.findall("proto[@name='wlan_radio']/field[@name='wlan_radio.duration']")  [0].get('show')
    dump['wlan_radio.preamble']  = frame.findall("proto[@name='wlan_radio']//field[@name='wlan_radio.preamble']") [0].get('show')
    dump['wlan_radio.ifs']       = frame.findall("proto[@name='wlan_radio']//field[@name='wlan_radio.ifs']")      [0].get('show')
    dump['wlan_radio.start_tsf'] = frame.findall("proto[@name='wlan_radio']//field[@name='wlan_radio.start_tsf']")[0].get('show')
    dump['wlan_radio.end_tsf']   = frame.findall("proto[@name='wlan_radio']//field[@name='wlan_radio.end_tsf']")  [0].get('show')

    dump['_fields_']    = {name.strip(): f['val'] for name, f in fields.items()}
    # dump.update({name.strip(): f['val'] for name, f in fields.items()})
    
    print >>options.write_file, json.dumps(dump)
    # print(json.dumps(dump), file = options.write_file)    # python3
    options.write_file.flush()
    

def get_str_ie(fields, mac_address, vendor):
    str_ie = ""
    str_ie += "MAC address: " + mac_address + " (" + vendor + ")\n"
    nb_devices = len(mac_addresses)
    m = max([len(x) for x in fields])
    title_one_in_x = "One in x devices have this value"
    l_title_one_in_x = len(title_one_in_x)
    str_ie += "Field " + " " * (m-5) + "| Entropy | " + title_one_in_x + " | value\n"
    # Group equal fields (we do it for cli display, but not for the dendrogram)
    fields_grouped = fields.copy()
    for name, field in sorted(fields_grouped.items()):
        # We can't loop over a dict we modify
        if name not in fields_grouped:
            continue
        name_sim = name + ' '
        while name_sim in fields_grouped:
            fields_grouped[name]['val'] += ';' + fields_grouped[name_sim]['val']
            del fields_grouped[name_sim]
            name_sim = name_sim + ' '
        fields_grouped[name]['entropy'] = calculate_entropy(name, fields_grouped[name]['val'])
        if name in db:
            if fields_grouped[name]['val'] in db[name]:
                nb_seen = float(db[name][fields_grouped[name]['val']])
            else:
                nb_seen = 1.0
        else:
            nb_seen = 1.0
        fields[name]['one_in_x'] = nb_devices / nb_seen
    # total
    total = []
    for key, val in sorted(fields_grouped.items()):
        vals = str(key + ':' + str(val['val']))
        total.append(vals)
    sha256 = hashlib.sha256()
    sha256.update("-".join(total))
    total_str = sha256.hexdigest()
    fields_grouped['total'] = {}
    fields_grouped['total']['entropy'] = calculate_entropy('total', total_str)
    if total_str in totals:
        fields_grouped['total']['one_in_x'] = "{0:.2f}".format(nb_devices / totals[total])
    else:
        fields_grouped['total']['one_in_x'] = nb_devices
    fields_grouped['total']['val'] = total_str
    # display
    for name, field in sorted(fields_grouped.items(), reverse=True, key=lambda t: t[1]['entropy']):
        sep = get_nb_spaces(field['entropy'], 10) * " "
        nb_spaces_one_in_x = get_nb_spaces(field['one_in_x'], float(nb_devices))
        sep2 = nb_spaces_one_in_x * " " + (l_title_one_in_x - len(str(nb_devices)) - 4) * " "
        str_ie += name + " " * (m - len(name) + 1) + "|" + sep + "  " + "{0:.3f}".format(field['entropy']) + " |" + sep2 + ' ' + "{0:.3f}".format(field['one_in_x']) + " | " + field['val'] + "\n"
    if total_str in totals:
        str_ie += "One in " + fields_grouped['total']['one_in_x'] + " devices share this signature\n"
    else:
        str_ie += "This device is unique among the " + str(nb_devices) + " devices in the database\n"
    if convert_to_hashed_value(mac_address) in mac_addresses:
        str_ie += "Device already in database\n"
    if not options.interactive and is_LA_bit_set(mac_address):
        # In interactive mode, random MAC are added anyway
        str_ie += "Locally Administered bit set, not adding to the database\n"
    return str_ie

def create_dendrograms(d, fields):
    G = nx.DiGraph(d)
    nodes = G.nodes()
    leaves      = set( n for n in nodes if G.out_degree(n) == 0 )
    inner_nodes = [ n for n in nodes if G.out_degree(n) > 0 ]
    # Compute the size of each subtree
    subtree = dict( (n, [n]) for n in leaves )
    for u in inner_nodes:
        children = set()
        node_list = list(d[u])
        while len(node_list) > 0:
            v = node_list.pop(0)
            children.add( v )
            node_list += d[v]
        subtree[u] = sorted(children & leaves)
    inner_nodes.sort(key=lambda n: len(subtree[n])) # <-- order inner nodes ascending by subtree size, root is last
    # Construct the linkage matrix
    leaves = sorted(leaves)
    index  = dict( (tuple([n]), i) for i, n in enumerate(leaves) )
    entropies = [None] * len(leaves)
    lab = [None] * len(leaves)
    Z = []
    k = len(leaves)
    for i, n in enumerate(inner_nodes):
        children = d[n]
        x = children[0]
        for y in children[1:]:
            z = tuple(sorted(subtree[x] + subtree[y]))
            i = index[tuple(subtree[x])]
            j = index[tuple(subtree[y])]
            entropy_parent = 0
            for child in subtree[n]:
                if G.out_degree(child) == 0:
                    entropy_parent += fields[child]['entropy']
                    entropies[index[tuple([child])]] = fields[child]['entropy']
            Z.append([i, j, float(entropy_parent), len(z)]) # <-- float is required by the dendrogram function
            index[z] = k
            subtree[z] = list(z)
            x = z
            k += 1
    # Visualize
    dendrograms.append(Z) # Caution: lst_devices.nb_dev must be correct
    for i in range(len(leaves)):
        lab[i] = leaves[i].rstrip(' ') + ' (' + "%.3g" % entropies[i] + ')'
    labels.append(lab)

def new_frame_xml(f):
    global db
    global mac_addresses
    global totals
    seen = {}
    total = []
    mac_address = f.findall("proto[@name='wlan']/field[@name='wlan.sa']")[0].get('show')
    if options.interactive or (not options.interactive and mac_address not in devices_seen_this_session):
        print_frame(f, mac_address)
        #show_dendrogram()
        #sys.exit(0)
    devices_seen_this_session.add(mac_address)
    if convert_to_hashed_value(mac_address) in mac_addresses:
        return
        #pass
    if not options.interactive and is_LA_bit_set(mac_address):
        # In interactive mode, random MAC are added anyway
        return
    print "Adding device to the database"
    mac_addresses.append(convert_to_hashed_value(mac_address))
    print mac_address
    
    # all subfields at any depth
    fields = f.findall("proto[@name='wlan']//*field")
    for field in fields:
        subfields = field.findall('field')
        # Only use leaf nodes
        # Non-leaf nodes repeat values in the leaves
        if subfields == []:
            name = field.get('name')
            if name == 'wlan.ssid' or name == 'wlan.ds.current_channel':
                continue
            val = field.get('value')
            if val == None:
                val = ''
            if name in seen:
                seen[name].append(val)
            else:
                seen[name] = [val]
    for key, val in seen.items():
        vals = ';'.join(val)
        db_add(key, vals)
        total.append(vals)
    total_str = ";".join(total)
    if total_str in totals:
        totals[total_str] += 1
    else:
        totals[total_str] = 1

def save_db():
    global database_already_saved
    if not database_already_saved:
        print "Saving database..."
        db_file = open(DB_FILE, 'wb')
        pickle.dump(db, db_file)
        pickle.dump(totals, db_file)
        pickle.dump(mac_addresses, db_file)
        db_file.close()
        database_already_saved = True

def dump_db():
    global db
    if not db:
        print "Empty database"
        return
    fields = {}
    lengths = [len(x) for x in db.keys()]
    if not lengths:
        print "Error: database is empty. Run panoptiphone.sh first!"
        sys.exit(1)
    m = max(lengths)
    sep = " "
    sep2 = " "
    nb_devices = len(mac_addresses)
    print nb_devices, "devices in the database"
    print "Information element", " " * (m - 19), "|", "Entropy", "|", "Aff dev", "|", "Number of values"
    for field, val in db.items():
        fields[field] = {}
        fields[field]['entropy'] = calculate_entropy_total(field)
        fields[field]['nb_val'] = len(val) + 1 # absence of a value is a value
        fields[field]['aff'] = sum(db[field].values())/float(nb_devices) * 100
    for name, field in sorted(fields.items(), reverse=True, key=lambda t: t[1]['entropy']):
        print name, " " * (m - len(name)), "| " + sep, "{0:.3f}".format(field['entropy']), "|", "{0:.2f}".format(field['aff']), " |" + sep2 , field['nb_val']
    print "total", " " * (m - len("total")), "|" + sep, '     ?', "|" + sep2 + "  -   | " , sum(totals.values())
    nb_unique_devices = 0
    for fingerprint in totals:
        if totals[fingerprint] == 1:
            nb_unique_devices += 1
    print nb_unique_devices, "devices (" + "{0:.2f}".format(float(nb_unique_devices)/nb_devices * 100) + "%) are unique in the database"

def dump_values(key):
    if key != 'total':
        m = max([len(x) for x in db[key].keys()])
        print "Value", " " * (m - 5), "|", "Number of times seen"
        for val in sorted(db[key], key=db[key].get, reverse=True):
            print val, " " * (m - len(val)), "|", int(db[key][val])
    else:
        print "Value", " |", "Number of times seen"
        for val in sorted(totals, key=totals.get, reverse=True):
            print val, " |", int(totals[val])

def signal_handler(signal, frame):
    save_db()
    sys.exit(0)

def load_db():
    global db
    global totals
    global mac_addresses
    if os.path.isfile(DB_FILE):
        db_file = open(DB_FILE, 'rb')
        db = pickle.load(db_file)
        totals = pickle.load(db_file)
        mac_addresses = pickle.load(db_file)
        db_file.close()

def load_OUIs():
    global OUIs
    if os.path.isfile(OUI_FILE):
        oui_file = open(OUI_FILE, 'r')
        for l in oui_file:
            infos = l.split("(hex)")
            mac = infos[0].strip().replace("-", ":").lower()
            vendor = infos[1].strip()
            OUIs[mac] = vendor
    else:
        print "Could not find OUI file"
        sys.exit(1)

class GUI():
    win = None
    label = None
    frame = None
    btn_dendrogram = None
    btn_close = None
    lst_devices = None
    canvas = None
    toolbar = None
    def __init__(self):
        self.win = Tk()
        self.label = Label(self.win, text="Devices")
        self.label.pack()
        self.frame = Frame(self.win)
        self.frame.pack(side='left', fill='both', expand=False)
        self.btn_dendrogram = Button(self.frame, text="Show Information Elements", command=action_btn_show_ie)
        self.btn_close = Button(self.frame, text="Close", command=exit_program)
        self.btn_close.pack(side="bottom")
        self.btn_dendrogram.pack(side="bottom")
        self.lst_devices = Lst_devices(self.frame)
        self.win.protocol("WM_DELETE_WINDOW", exit_program)

    def add_dendrogram(self, fig):
        if self.canvas is not None:
            self.canvas.get_tk_widget().destroy()
        self.canvas = FigureCanvasTkAgg(fig, self.win)
        self.canvas.show()
        if self.toolbar is not None:
            self.toolbar.destroy()
        self.toolbar = NavigationToolbar2TkAgg(self.canvas, self.win)
        self.toolbar.update()
        self.canvas.get_tk_widget().pack(side="right", fill=BOTH, expand=True)

class Lst_devices():
    #http://effbot.org/tkinterbook/listbox.htm
    def __init__(self, frame):
        scrollbar = Scrollbar(frame, orient="vertical")
        self.list = Listbox(frame, selectmode=EXTENDED, width=50, yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.list.yview)
        self.list.pack(fill=BOTH, expand=False, side="left")
        scrollbar.pack(side="left", fill="y")
        self.current = None

    def add(self, mac_address, name=""):
        self.list.insert(len(devices_seen_this_session), mac_address + ' ' + name)
        self.list.pack(fill=BOTH, expand=False, side="left")

def show_dendrogram(index):
    x_coords = {}
    y_coords = {}
    fig, axe = plt.subplots(1, 1)
    ddata = dendrogram(dendrograms[index], labels=labels[index],
                     leaf_rotation=0.,
                     leaf_font_size=8,
                       orientation='left',
                       ax=axe,
                     show_contracted=True)
    for i, d, c in zip(ddata['icoord'], ddata['dcoord'], ddata['color_list']):
        x = 0.5 * sum(i[1:3])
        y = d[1]
        key = str(y) + c
        if key in x_coords:
            x_coords[key].append(x)
        else:
            x_coords[key] = [x]
            y_coords[key] = y
    for key in y_coords:
        sorted_x_coords = sorted(x_coords[key])
        final_x = (sorted_x_coords[0] + sorted_x_coords[-1]) / 2.0
        y = y_coords[key]
        axe.plot(y_coords[key], final_x, 'o', c=c)
        axe.annotate("%.3g" % y, (y, final_x), xytext=(-20, 0),
                     textcoords='offset points',
                     va='center', ha='center')
    fig.tight_layout()
    if gui is not None:
        gui.add_dendrogram(fig)

def action_btn_show_ie():
    selection = gui.lst_devices.list.curselection()
    if not selection: return
    index = selection[0]
    print str_ies[index]
    show_dendrogram(index)

def exit_program():
    gui.win.destroy()
    gui.win.quit()
    save_db()

def draw_GUI():
    global gui
    gui = GUI()
    gui.win.mainloop()

def help():
    print "Usage: python2 panoptiphone.py [-dgivh]"
    print "If you don't know what you're doing, you probably want to run panoptiphone.sh"
    sys.exit(0)

def parse_options():
    global options
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'df:ghiv:wx', ['help'])
    except getopt.GetoptError as err:
        print "Error: ", str(err)
        sys.exit(1)
    for o, arg in opts:
        if o == '-d':
            options.dump_db = True
        elif o == '-g':
            options.graphical = True
        elif o == '-i':
            options.interactive = True
        elif o == '-v':
            options.dump_values = arg
        elif o == '-w':
            options.write_file = open(arg, 'at')
        elif o == '-h' or o == '--help':
            help()

def normal_execution():
    if options.dump_db == True:
        dump_db()
    elif options.dump_values != False:
        dump_values(options.dump_values)
    else:
        # For stream reading
        cur_packet = None
        for event, elem in xml.etree.ElementTree.iterparse(options.f):
            if elem.tag == 'packet':
                new_frame_xml(elem)
                elem.clear()
    save_db()

if __name__=='__main__':
    signal.signal(signal.SIGINT, signal_handler)
    load_db()
    load_OUIs()
    parse_options()
    t = threading.Thread(target=normal_execution)
    t.start()
    if options.graphical:
        draw_GUI()
