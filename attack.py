from manager import print_regular
from manager import print_header
from manager import print_errors
from manager import bash
from manager import search
from manager import channel_changing
from manager import exit_and_cleanup
from manager import monitor_mode
from manager import Fore
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt

ap_list = []


def finding_networks(pkt):
    """
    uses for scapy.sniff function.
    first the function check if there is a valid mac address in the pkt
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


def get_ap(index: int):
    if index in range(len(ap_list)):
        return ap_list[index]
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
            print(self.sniffer)
            print_regular('Great! Sniffer interface is {}'.format(self.sniffer)) if search(user_input, output) else print_errors(
                'The interface {} is not part of the list, Please insert one of the interfaces above {}\n'.format(
                    user_input, Fore.WHITE))

        output = os.popen('iwconfig').read()
        print(output)  # display the interfaces
        while self.ap == 'invalid':
            user_input = input('Please enter the interface name that will be used for Fake Access Point , for example '
                               '\"wlan1\" \n')
            self.ap = user_input if search(user_input, output) else 'invalid'
            print_regular(
                'Great! Fake Access Point interface is {}'.format(self.sniffer)) if search(user_input, output) else print_errors(
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
                              'more network Please type \'Rescan\' for a new networks scan')
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
    def get_client_index:
        pass

