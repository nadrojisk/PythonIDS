"""
Main IDS Driver

Author: Jordan Sosnowski, Charles Harper, John David Watts
Date: Dec 6, 2019
"""

import multiprocessing
import ids_nmap
import ids_ettercap
import ids_responder

INTERFACE = 'etho'


def main():
    """
    Main driver for the IDS

    Uses multiprocessing to run each detection algorithm

    """
    print('Sniffing...')

    xmas = multiprocessing.Process(
        target=ids_nmap.xmas_signature_detection, kwargs={'interface': INTERFACE, 'continuous': True})
    ack = multiprocessing.Process(
        target=ids_nmap.ack_heuristic_detection, kwargs={'interface': INTERFACE, 'continuous': True})
    syn = multiprocessing.Process(
        target=ids_nmap.syn_heuristic_detection(), kwargs={'interface': INTERFACE, 'continuous': True})
    ettercap_1 = multiprocessing.Process(
        target=ids_ettercap.heuristic_detection, kwargs={'interface': INTERFACE, 'continuous': True})
    ettercap_2 = multiprocessing.Process(
        target=ids_ettercap.behavioral_detection, kwargs={'interface': INTERFACE, 'continuous': True})
    responder = multiprocessing.Process(
        target=ids_responder.behavioral_detection, kwargs={'interface': INTERFACE, 'continuous': True})

    # starting individual threads
    xmas.start()
    ack.start()
    syn.start()
    ettercap_1.start()
    ettercap_2.start()
    responder.start()

    # wait until threads complete
    xmas.join()
    ack.join()
    syn.join()
    ettercap_1.join()
    ettercap_2.join()
    responder.join()
    print("Done!")


main()
