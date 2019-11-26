# x mas
import sniffer

"""
An IDS system for detecting nmap xmas attacks, syn attacks, and ack attacks
"""


def xmas_detection(file):

    host_in_question = ""
    previous_arp_type = ""
    concurrent_arp_req_count = 0
    arp_req_count = 0
    arp_resp_count = 0
    arp_req_threshold = 10
    concurrent_arp_reply_threshold = 4
    concurrent_arp_reply_count = 0

    capture = sniffer.read_cap(file)
    for packet in capture:
        if packet.transport_layer == 'TCP':
            tcp_layer = packet.layers[2]
            if tcp_layer.flags == '0x00000029':
                print(f'XMAS ATTACK in packet number: {packet.number}')


def main():
    xmas_detection('pcaps/nmap/xmas.pcapng')


main()
