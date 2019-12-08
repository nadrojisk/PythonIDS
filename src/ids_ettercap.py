"""
Ettercap detection module

Author: Charles Harper
Date: Nov 12, 2019
"""

import sniffer

CONCURRENT_ARP_REPLY_THRESHOLD = 4

def heuristic_detection(file=None, **kwargs):
    """
    ARP Poisoning host discovery detection function

    Observes ARP traffic, looking for an abnormal number of concurrent ARP requests. 
    Given a specific threshold defined as "CONCURRENT_ARP_REPLY_THRESHOLD", this function 
    counts the number concurrent ARP requests and compares it to the threshold. If the
    count exceeds the threshold, each following ARP request from the sender is flagged
    as an ARP Poisoning packet and a warning is issued and returned to the ids system.
    """
    capture = sniffer.get_capture(file, **kwargs)
    was_detected = False
    host_in_question = ""
    concurrent_arp_req_count = 0
    arp_req_threshold = 30
    request = '1'
    reply = '2'

    for packet in capture:
        if 'arp' in packet: #if it is an ARP packet
            if packet.arp.opcode == request:  # if the arp packet is an arp request
                if host_in_question == "":
                    host_in_question = packet.eth.src  # set first MAC SRC address for ARP messages
                elif host_in_question == packet.eth.src:  # if the current mac equals the previous mac
                    concurrent_arp_req_count += 1
                else:
                    host_in_question = packet.eth.src
                    concurrent_arp_req_count = 0
                # if the number of concurrent arp_requests with the same src exceeds our threshold there's a problem
                if concurrent_arp_req_count >= arp_req_threshold:
                    print("ARP POISONING DETECTED!!! FLAGGED PACKET:", packet.number)
                    was_detected = True
    return was_detected


def behavioral_detection(file=None, **kwargs):
    """
    Gratuitous ARP detection function

    Observes the behavior of the ARP traffic on the network, and flags packets contributing to an abnormal 
    ARP reply to ARP request ratio.
    """
    capture = sniffer.get_capture(file, **kwargs)
    was_detected = False
    previous_arp_type = None
    current_arp_type = None
    concurrent_arp_reply_count = 0
    request = '1'
    reply = '2'

    for packet in capture:
        if 'arp' in packet:
            current_arp_type = packet.arp.opcode
            if current_arp_type == reply:  # if current ARP message is a reply
                if previous_arp_type == request: # if the previous ARP message was a request
                    # clear the previous message and move on
                    previous_arp_type = current_arp_type
                    concurrent_arp_reply_count = 0
                else: # if the previous ARP was a reply
                    concurrent_arp_reply_count += 1
                    if concurrent_arp_reply_count > CONCURRENT_ARP_REPLY_THRESHOLD: # when the number of concurrent replies reaches Threshold
                        print(
                            "GRATUITOUS ARP DETECTED!!! FLAGGED PACKET:", packet.number)
                        was_detected = True
            else:  # if current ARP message it is a request
                previous_arp_type = request
    return was_detected