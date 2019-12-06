# x mas
import sniffer
from collections import defaultdict

"""
An IDS system for detecting nmap xmas attacks, syn attacks, and ack attacks
"""


def xmas_signature_detection(file):
    capture = sniffer.read_cap(file)
    for packet in capture:
        if packet.transport_layer == 'TCP':
            if packet.tcp.flags == '0x00000029':
                print(f'XMAS ATTACK in packet number: {packet.number}')

def ack_signature_detection(file):
    capture = sniffer.read_cap(file)
    filter = defaultdict(lambda: defaultdict(int))
    for packet in capture:
        try:
            if packet.transport_layer == 'TCP':
                if packet.ip.addr in filter:
                    filter[packet.ip.addr].add(packet.tcp.port)
                    if len(filter[packet.ip.addr]) > 30:
                        print("ACK Attack Detected")
                        
                else:
                    filter[packet.ip.addr] = set()
        except:
            pass


def main():
    # xmas_signature_detection('pcaps/nmap/xmas_ubuntu.pcapng')

    ack_signature_detection('pcaps/normal_data.pcapng')

main()
