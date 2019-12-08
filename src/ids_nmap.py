"""
An IDS system for detecting nmap xmas attacks, ack attacks, and syn attacks

Author: Jordan Sosnowski
Date: Nov 26 2019

"""

import collections
import sniffer


MAX_UNIQUE_PORTS = 10


def xmas_signature_detection(file=None, **kwargs):
    """
    xmas detection function

    uses the signature of TCP Flag == 0x29
    """
    capture = sniffer.get_capture(file, **kwargs)
    detected = False

    for packet in capture:
        # ensure packet is TCP as xmas attacks run over TCP
        if packet.transport_layer == 'TCP':
            # ensure that the only flags set are the push, urgent, and final flags
            # usually those flags should not be set, and if they are its probably
            # an xmas attack
            if int(packet.tcp.flags, 16) == 41:  # '0x00000029'
                print(f'XMAS ATTACK in packet number: {packet.number}')
                detected = True
    return detected


def ack_heuristic_detection(file=None, **kwargs):
    """
    ack detection function

    uses the heursitic of uniq ports > MAX_UNIQUE_PORTS and if
    TCP flag == 0x10
    """
    capture = sniffer.get_capture(file, **kwargs)
    uniq_ip = collections.defaultdict(set)
    detected = False

    for packet in capture:
        # ensure packet is using TCP as ack attacks run over TCP
        if packet.transport_layer == 'TCP':
            # ensure packet is only setting the ACK flag
            if int(packet.tcp.flags, 16) == 16:  # 0x10
                uniq_ip[packet.ip.addr].add(packet.tcp.dstport)

                # if the number of unique dst ports are more then MAX_UNIQUE_PORTS flag it
                if len(uniq_ip[packet.ip.addr]) > MAX_UNIQUE_PORTS:
                    print(f'ACK ATTACK in packet number: {packet.number}')
                    detected = True

    return detected


def syn_heuristic_detection(file=None, **kwargs):
    """
    syn detection function

    uses the heursitic of uniq ports > MAX_UNIQUE_PORTS and if
    TCP flag == 0x2
    """
    capture = sniffer.get_capture(file, **kwargs)
    uniq_ip = collections.defaultdict(set)
    detected = False

    for packet in capture:
        # ensure packet is using TCP as syn attacks run over TCP
        if packet.transport_layer == 'TCP':
            # ensure packet is only setting the SYN flag
            if int(packet.tcp.flags, 16) == 2:
                uniq_ip[packet.ip.addr].add(packet.tcp.dstport)

                # if the number of unique dst ports are more than MAX_UNIQUE_PORTS flag it
                if len(uniq_ip[packet.ip.addr]) > MAX_UNIQUE_PORTS:
                    print(f'SYN ATTACK in packet number: {packet.number}')
                    detected = True

    return detected
