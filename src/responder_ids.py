# x mas
import sniffer
import collections


"""
An IDS system for detecting responder attacks

Author: John David Watts
Date: Decemeber 12 2019

"""

MAX_UNIQUE_PORTS = 10
DOMAIN_IP = '192.168.150.201'


def responder_signature_detection(file=None, **kwargs):
    capture = sniffer.get_capture(file, **kwargs)
    detected = False

    for packet in capture:
        # ensure packet is either an 'NBNS' or 'LLMNR' as responder attacks run through these protocols
        try:
            if ('nbns' in packet or 'llmnr' in packet) and packet.ip.src != DOMAIN_IP:
                print(f'Responder ATTACK deteced in packet number: {packet.number}')
                detected = True
        except:
        	pass
    return detected

responder_signature_detection('attack.pcapng')


