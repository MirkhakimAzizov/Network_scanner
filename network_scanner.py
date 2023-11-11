#!/usr/bin/env python

import scapy.all as scapy
import optparse
def input_ip():
    parser = optparse.OptionParser()
    parser.add_option("-ip", "--ipAddress", dest="ip", help="IP address")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify an IP address, use --help for more info")
    return options
    print(options.ip)
def scan(ip):
    # scapy.arping(ip)
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answerad_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answerad_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n---------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

scan_ip = input_ip()
scan_result = scan(scan_ip.ip)
print_result(scan_result)
