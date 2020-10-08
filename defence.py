from manager import print_regular
from manager import print_header
from manager import print_errors
from manager import bash
from manager import search
from manager import channel_changing
from manager import exit_and_cleanup
from manager import monitor_mode
from manager import Fore


class Defence:

    def __init__(self, ap_index):
        self.ap_index = ap_index

    def display_problem(self, networks):
        not_duplicates = []
        duplicates = []
        for network in networks:
            if network[0] in not_duplicates:
                duplicates.append(network)
            else:
                not_duplicates.append(network[0])
        print_header('Duplicates')
        if len(duplicates) > 0:
            duplicates = list(dict.fromkeys(duplicates))
            for index in range(len(duplicates)):
                print_regular(
                    '{} BSSID = {} , MAC_ADDRESS = {}\n'.format(index, duplicates[index][0], duplicates[0][1]))
            print_header('Preventing attack')

        else:
            print_errors('The Access Point have failed to upload please...')
            exit_and_cleanup(-1, 'Demonstration has failed , some thing wrong with AP')
