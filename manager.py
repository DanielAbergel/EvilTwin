import os
import sys
import time
import re
from colorama import Fore


def monitor_mode(interface: str) -> None:
    """
    Change the interface mode to monitor mode,
    This will used by sniffer interface to sniff the packets.
    for more information : Please enter
    https://linux.die.net/man/8/iwconfig
    """
    bash('ifconfig ' + interface + ' down')
    bash('iwconfig ' + interface + ' mode monitor')
    bash('ifconfig ' + interface + ' up')


def search(word: str, text: str):
    result = text.find(word)
    return result != -1


def bash(command: str):
    return os.system(command)


def print_regular(message: str):
    print('{}{}'.format(Fore.WHITE, message))


def print_command(message: str):
    print('{}{}'.format(Fore.BLUE, message))


def print_errors(message: str):
    print('{}{}'.format(Fore.RED, message))


def print_header(message: str):
    print(Fore.WHITE)
    bash('figlet {}'.format(message))


def handle_user_result():
    return input('{}[1] Perform Evil Twin Attack\n'
                 '[2] Perform Defence on Evil Twin Attack \n'
                 'Please select one of the options mentioned above, or write quit to quit the manager\n'.format(
        Fore.BLUE))


def start_evil_twin_attack():
    pass


def manage():
    print_header('Evil Twin Manager')
    print_command("Welcome To Evil Twin Manager")
    if os.geteuid():  # because scapy library must use root privileges.
        sys.exit('{}Perform exit() , Please run as root user , use sudo command , for more information please read '
                 'the README'.format(Fore.RED))

    while True:
        user_input = handle_user_result()
        if user_input == '1':
            start_evil_twin_attack()
            break
        elif user_input == '2':
            print_header('defence...')
            break
        elif user_input == 'quit':
            print_header('Bye Bye ...')
            exit(0)
        else:
            print_errors('Not a valid option please , Please try again.')


if __name__ == '__main__':
    manage()
