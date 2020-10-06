from manager import print_regular
from manager import print_header
from manager import print_errors
from manager import bash
from manager import search


class Attack:

    def __init__(self):
        """
        prepare the environment - stop all the running network processes
        """
        print_header('Prepare the Attack')
        bash('service NetworkManager stop')
        bash('airmon-ng check kill')
        bash('iwconfig')  # display the interfaces
        while self.sniffer != 'invalid':
            user_input = input('Please enter the interface name that will be used for sniffing , for example \"wlan0\"')
            search_result = search(user_input, bash('iwconfig'))
            self.sniffer = user_input if search_result else {'invalid'}
            print_regular('Great! Sniffer interface is {}'.format(self.sniffer)) if search_result else print_errors(
                'The interface {} is not part of the list, Please insert one of the interfaces above'.format(
                    self.sniffer))

        while self.ap != 'invalid':
            user_input = input('Please enter the interface name that will be used for Fake Access Point , for example '
                               '\"wlan1\"')
            self.ap = user_input if search(user_input, bash('iwconfig')) else {'invalid'}
            print_regular(
                'Great! Fake Access Point interface is {}'.format(self.sniffer)) if search_result else print_errors(
                'The interface {} is not part of the list, Please insert one of the interfaces above'.format(
                    self.ap))

        print_regular('change {} interface to monitor mode'.format(self.sniffer))
