#!/bin/sh

service NetworkManager start
service NetworkManager start
service hostapd stop
service apache2 stop
service dnsmasq stop
service rpcbind stop
killall dnsmasq
killall hostapd
rm -f build/hostapd.conf
rm -f build/dnsmasq.conf
systemctl enable systemd-resolved.service
systemctl start systemd-resolved
rm -rf build/
ifconfig ${SNIFFER} down
iwconfig ${SNIFFER} mode managed
ifconfig ${SNIFFER} up
ifconfig ${AP} down
iwconfig ${AP} mode managed
ifconfig ${AP} up
service network-manager restart

