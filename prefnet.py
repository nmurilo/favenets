#!/usr/bin/env python 
__author__    = "Nelson Murilo" 
__email__     = "nmurilo@gmail.com"
_copyright__ = "Copyright (c) 2011-2023 Pangeia Inc"  
__license__   = "AMS"
__version__   = "0.2"
__date__      = "2012-05-20"

# Update the OUI database (Linux): 
# cd /usr/share/pyshared/netaddr/eui
# python ieee.py 

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from netaddr import *

probe_list = [] 
def PacketHandler(pkt) :
   if pkt.type == 0 and pkt.subtype == 4 : 
      if pkt.info+pkt.addr2 not in probe_list : 
         if pkt.info != "" :
            probe_list.append(pkt.info+pkt.addr2)
            try: 
               oui = EUI(pkt.addr2).oui
               mac = oui.registration().org 
            except  NotRegisteredError:
               mac = "??" 
            print "%s(%s) [%s] "  %(pkt.addr2, mac, pkt.info)
try:
   # YOU MUST to put here your wifi interface in monitor mode 
   sniff(iface="mon0", prn = PacketHandler, lfilter=lambda p:Dot11ProbeReq in p)
except:
   print "prefnet: Interface in monitor mode not found\n" 
