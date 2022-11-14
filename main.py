import threading
import time
from ArpSpoofer import *
from nmap import *
import socket
import os
import subprocess
import re

# import dns.resolver
# avahi-resolve -a ip

if __name__ == '__main__':
    # pass

    bash = 'avahi-resolve -a 192.168.1.1'
    proc = subprocess.Popen(bash.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    output = proc.stdout.readline()
    str_with_t = " ".join(str(output.strip()).replace('b', "").split('\\t'))
    print(str_with_t)
    # nm = nmap.PortScanner()
    # nm.scan(hosts='192.168.1.0/24', arguments='-sn')
    # print(socket.gethostbyaddr(nm.all_hosts()[4]))
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

    # 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
    # See PyCharm help at https://www.jetbrains.com/help/pycharm/
