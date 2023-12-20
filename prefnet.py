#!/usr/bin/env python3
__author__    = "Nelson Murilo" 
__email__     = "nmurilo@gmail.com"
_copyright__ = "Copyright (c) 2023"
__license__   = "AMS"
__version__   = "0.3"
__date__      = "2023-11-14"

from scapy.all import sniff
from ouilookup import OuiLookup
import getopt,sys

opt="ui:"
interface="wlan0" # ALREADY MUST BE IN MONITOR MODE  
probe_list = []

try:
   options, args = getopt.getopt(sys.argv[1:], opt)
except:
   print ("Usage: prefnet.py [-u]\n\t-u: Update OUI database\n\t-i interface")
   exit (1)

for name, value in options:
   if name == "-u":
      print("Updating oui database...\n")
      OuiLookup().update()
   elif name == "-i":
      interface=value
   else:
      print ("Usage: prefnet.py [-u]\n\t-u: Update OUI database\n\t-i interface")
      exit (1)

def PacketHandler(pkt):
#   print(f"type={pkt.type}, subtype={pkt.subtype}") # DEBUG
   if pkt.type == 0 and pkt.subtype == 4:
      info=pkt.info.decode('ascii','ígnore')
      addr=str(pkt.addr2)
      if info+addr not in probe_list:
         if info != "":
               probe_list.append(info+addr)
            try:
               mac = str(OuiLookup().query(addr)).split("'")[3]
            except:
               mac = "-"
            print(f"{addr}({mac}): {info}")
try:
   sniff(iface=interface, prn=PacketHandler,monitor=True)
except OSError as error:
   print(f"prefnet: {error}")
