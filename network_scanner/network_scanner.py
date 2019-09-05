#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_ip_range():
    ip_range = argparse.ArgumentParser()
    ip_range.add_argument("-t", "--target", dest="target", help="ip range to scan")
    options = ip_range.parse_args()
    if not options.target:
        ip_range.error("[-] please enter ip range. use --help for more info")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list =[]
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)

    return (client_list)

def print_result(results_list):
    print("IP\t\t\tMAC Address\n.........................................")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_ip_range()
scan_result = scan(options.target)
print_result(scan_result)