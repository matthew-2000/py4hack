from scapy.all import *

def pkt_callback(pkt):
    print("Pacchetto ricevuto:", pkt.summary())

# Sniffa 5 pacchetti dalla rete
sniff(filter="tcp port 80", count=5, prn=pkt_callback)