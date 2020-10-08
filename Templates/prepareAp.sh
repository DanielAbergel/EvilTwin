#!/bin/sh

systemctl disable systemd-resolved.service
systemctl stop systemd-resolved
service NetworkManager stop

ifconfig ${INTERFACE} 10.0.0.1 netmask 255.255.255.0
airmon-ng check kill
ifconfig
route add default gw 10.0.0.1
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT #

dnsmasq -C dnsmasq.conf
hostapd hostapd.conf -B

service apache2 start
route add default gw 10.0.0.1