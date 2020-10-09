<p align="center">
  <img src="https://user-images.githubusercontent.com/44754325/95581514-d48b8f00-0a41-11eb-8864-b0714a71f2c0.png">
</p>

# Evil Twin Attack/Defence
## Introduction:
This project represent a Evil Twin Attack and Defence tool. 
using python and open source libraries (scapy etc.).
This tool is an exercise in the framework of cyber course in our University.
The purpose of this project is to create a tool to perform an evil twin attack and defence.
In this attack, we set up a fake access point that will impersonating to the victim access point we want to perform the attack on
 to steal the victim's details.

## Execute Evil Twin Attack
### Installing the environment:
Clone our project and using the terminal go to the project clone directory.
As part of the tool we create a ```install.sh``` script , that would help you to install the attack environment
if one of the libraries is failed to install , please see the error message and try to install again. all the libraries that part of the **install.sh** script are mandatory. without them the tool will not work as expected

Run this command:

```sudo sh install.sh```

### Lunch the Attack/Defence

After installing the mandatory libraries. Please notice that it is very important to execute this command inside the cloned directory.

to run the tool just execute the command

```sudo python3 manager.py```

## Requirements:
##### Hardware :
* A Laptop with WIFI adapter.
* Tenda wireless adapter.

##### Software Used:
* Ubuntu Linux (Attacker) **In Our enviroment we use Ubuntu 20.04.1 LTS**.
* The libraries we mentioned above.

## Knowledge
As part of this tool we used scapy library to perform sniffing and deauthenticating (using Dot11Deauth and RadioTap) 
users from the network. within this library there is Dot11 packets that will give us information about the packet destenation and sender mac address and more information that we used to perform the attack.
to create the access point we used hostapd and dnsmaskq tools to redirect the traffic to our getway.

###Links that we used.
    
https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy

https://rootsh3ll.com/evil-twin-attack/

https://linux.die.net/man/8/iwconfig

https://scapy.readthedocs.io/en/latest/api/scapy.layers.dot11.html






