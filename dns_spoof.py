import netfilterqueue
import scapy.all as scapy

def filter_pkt(pkt):
    scapy_converted_pkt = scapy.IP(pkt.get_payload())
    if scapy_converted_pkt.haslayer(scapy.DNSRR()):
        print(scapy_converted_pkt.show())
    pkt.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, filter_pkt)
queue.run()