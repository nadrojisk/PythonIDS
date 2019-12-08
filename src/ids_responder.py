"""
An IDS system for detecting responder attacks

Author: John David Watts
Date: Decemeber 12 2019
"""

import sniffer


DOMAIN_IP = '192.168.150.201'  # should change per network


def behavioral_detection(file=None, **kwargs):
    """
    function to detect responders spoofing attacks

    assumes that only one IP is acting as the domain controller and
    assume as an admin you know the IP
    """
    capture = sniffer.get_capture(file, **kwargs)
    detected = False

    for packet in capture:
        # ensure packet is either an 'NBNS' or 'LLMNR'
        # as responder attacks run through these protocols
        try:
            if ('nbns' in packet or 'llmnr' in packet) and packet.ip.src != DOMAIN_IP:
                print(
                    f'Responder ATTACK deteced in packet number: {packet.number}')
                detected = True
        except AttributeError:
            # some LLMNR packets are transmitted via link layer and not the internet layer
            # meaning they only have MAC addresses and not IP
            pass
    return detected
