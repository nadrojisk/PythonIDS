# x mas
import sniffer
from collections import defaultdict

"""
An IDS system for detecting nmap xmas attacks, syn attacks, and ack attacks
"""


def xmas_signature_detection(file):
    capture = sniffer.read_cap(file)
    detected= False
    for packet in capture:
        if packet.transport_layer == 'TCP':
            if packet.tcp.flags == '0x00000029':
                print(f'XMAS ATTACK in packet number: {packet.number}')
                detected=True
    return detected

def ack_signature_detection(file):
    capture = sniffer.read_cap(file)
    filter = {}
    detected = False
    for packet in capture:
        try:
            if packet.transport_layer == 'TCP' :
                if  int(packet.tcp.flags,16) == 16:
                    if packet.ip.addr in filter:
                        filter[packet.ip.addr].add(packet.tcp.dstport)
                        if len(filter[packet.ip.addr]) > 10:
                            print("ACK Attack Detected")
                            detected = True
                    else:
                        filter[packet.ip.addr] = set()
        except:
            pass
    return detected

def syn_signature_detection(file):
    capture = sniffer.read_cap(file)
    filter = {}
    detected = False
    for packet in capture:
        try:
            if packet.transport_layer == 'TCP' :
                if  int(packet.tcp.flags,16) == 2:
                    if packet.ip.addr in filter:
                        filter[packet.ip.addr].add(packet.tcp.dstport)
                        if len(filter[packet.ip.addr]) > 10:
                            print("SYN Attack Detected")
                            detected = True
                    else:
                        filter[packet.ip.addr] = set()
        except:
            pass
    return detected


