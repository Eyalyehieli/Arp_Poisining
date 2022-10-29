#! /bin/sh
echo "Enter target ip:"
read target_ip
sudo iptables -I FORWARD -s $target_ip -j DROP
sudo iptables -I FORWARD -d $target_ip -j DROP
sudo iptables -I INPUT -s $target_ip -j DROP
sudo iptables -I INPUT -d $target_ip -j DROP
sudo iptables -I OUTPUT -s $target_ip -j DROP
sudo iptables -I OUTPUT -d $target_ip -j DROP
sudo python3 main.py
