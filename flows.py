import sys
from scapy.all import *

class Stream:
    def __init__(self, pkt):
        self.pkts = [pkt]
        self.src_ip = pkt[IP].src
        self.dst_ip = pkt[IP].dst
        self.sport = pkt.sport
        self.dport = pkt.dport
        self.protocol = pkt[IP].proto
        self.content = [pkt.load.decode(errors='ignore')] if pkt.haslayer('Raw') else []

    def update(self, pkt):
        self.pkts.append(pkt)
        if pkt.haslayer('Raw'):
            self.content.append(pkt.load.decode(errors='ignore'))
    

def parse_pcap(file_name):
    streams = {}
    pkts = rdpcap(file_name)
    for pkt in pkts:
        for pkt in pkts:
            if IP in pkt:
                proto = pkt[IP].proto
                if proto in [6, 17]:
                    five_tuple = None
                    if proto == 6:
                        five_tuple = (pkt[IP].src, pkt[IP].dst, pkt.sport, pkt.dport, proto)
                    elif proto == 17:
                        five_tuple = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, proto)
                    if five_tuple in streams:
                        streams[five_tuple].update(pkt)
                    else:
                        streams[five_tuple] = Stream(pkt)
    return streams
