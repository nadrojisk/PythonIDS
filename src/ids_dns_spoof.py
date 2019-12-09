"""
DNS Spoofing detection module

Author: Charles Harper
Date: Dec 18, 2019
"""
import sniffer

NETWORK_GATEWAY_ADDRESS = "--:--:--:--:--:--"

def dns_spoofing_detector(file=None, **kwargs):
    """
    DNS spoofing detector function

    Observes ongoing DNS traffic. Assuming the IDS user has provided the MAC address of the
    legitimate gateway, this function observes the MAC address of the host actively
    responding the DNS requests. If the MAC address of the active DNS responder does not
    match the provided MAC address, an attacker is spoofing DNS.
    """
    capture = sniffer.get_capture(file, **kwargs)
    was_detected = False
    packet_src = None
    packet_dst = None

    for packet in capture:
        if 'DNS' in packet:
            packet_src = packet.eth.src
            packet_dst = packet.eth.dst
            if packet_dst != NETWORK_GATEWAY_ADDRESS and packet_src != NETWORK_GATEWAY_ADDRESS:
                print("DNS SPOOFING DETECTED!!! Packet Number:",packet.number)
                print("src ip:",packet.ip.src,"src mac:", packet.eth.src)
                print("dst ip:",packet.ip.dst,"dst mac:",packet.eth.dst)
                was_detected = True
    return was_detected


