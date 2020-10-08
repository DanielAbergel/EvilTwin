#!/bin/sh

service NetworkManager start
service NetworkManager start
service hostapd stop
service apache2 stop
service dnsmasq stop
service rpcbind stop
killall dnsmasq
killall hostapd
rm -f hostapd.conf
rm -f dnsmasq.conf
systemctl enable systemd-resolved.service
systemctl start systemd-resolved