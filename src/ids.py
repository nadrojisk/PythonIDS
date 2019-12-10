"""
Main IDS Driver

Authors: Jordan Sosnowski, Charles Harper, 
John David Watts, and Tyler McGlawn

Date: Dec 6, 2019
"""
import sys
import multiprocessing
import os
import sniffer
import ids_nmap
import ids_ettercap
import ids_responder
import ids_ms17_010_psexec


def clear():

    # for windows
    if os.name == 'nt':
        _ = os.system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        _ = os.system('clear')


def main():
    """
    Main driver for the IDS

    Uses multiprocessing to run each detection algorithm

    """
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = sniffer.choose_interface()
    clear()
    print('Sniffing...')

    xmas = multiprocessing.Process(
        target=ids_nmap.xmas_signature_detection, kwargs={'interface': interface, 'continuous': True})
    ack = multiprocessing.Process(
        target=ids_nmap.ack_heuristic_detection, kwargs={'interface': interface, 'continuous': True})
    syn = multiprocessing.Process(
        target=ids_nmap.syn_heuristic_detection, kwargs={'interface': interface, 'continuous': True})
    ettercap_1 = multiprocessing.Process(
        target=ids_ettercap.heuristic_detection, kwargs={'interface': interface, 'continuous': True})
    ettercap_2 = multiprocessing.Process(
        target=ids_ettercap.behavioral_detection, kwargs={'interface': interface, 'continuous': True})
    responder = multiprocessing.Process(
        target=ids_responder.behavioral_detection, kwargs={'interface': interface, 'continuous': True})
    ms17_010_psexec = multiprocessing.Process(
        target=ids_ms17_010_psexec.signature_detection, kwargs={'interface': interface, 'continuous': True})

    # starting individual threads
    xmas.start()
    ack.start()
    syn.start()
    ettercap_1.start()
    ettercap_2.start()
    responder.start()
    ms17_010_psexec.start()

    # wait until threads complete
    xmas.join()
    ack.join()
    syn.join()
    ettercap_1.join()
    ettercap_2.join()
    responder.join()
    ms17_010_psexec.join()
    print("Done!")


main()
