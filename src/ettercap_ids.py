import sniffer

		#ARP POISONING CHECKS
		## 1. check the number of arp requests in a row over the network
		### if it exceeds 10 in a row, we know they're running network discovery
		### otherwise, it should be ok
		## 2. check if the arp reply contains information about duplicate-addresses
		### if it does, they're most likely running arp poisoning
		### if it isn't, it should be ok
		## 3. assuming they get passed the arp request count check, keep count of the number arp req to arp replys
		### if the replies far exceeds the replies, we know that an arp spoof is taking place
		### otherwise, we should be ok

		#depricated function 2 as it's a built-in warning associated with wireshark (i think), and will not work with tshark

def heuristic_detection(file=None, **kwargs):
	capture = sniffer.get_capture(file, **kwargs)
	was_detected = False
	host_in_question = ""
	concurrent_arp_req_count = 0
	arp_req_threshold = 30

	for packet in capture:
		if 'arp' in packet: 
			if packet.arp.opcode == '1': #if the arp packet is an arp request
				if host_in_question == "":
					host_in_question = packet.eth.src # set first MAC SRC address for ARP messages
				elif host_in_question == packet.eth.src: # if the current mac equals the previous mac
					concurrent_arp_req_count += 1
				else:
					host_in_question = packet.eth.src
					concurrent_arp_req_count = 0
				if concurrent_arp_req_count >= arp_req_threshold: # if the number of concurrent arp_requests with the same src exceeds our threshold there's a problem
					print("ARP POISONING DETECTED!!! FLAGGED PACKET:", packet.number)
					was_detected = True
	return was_detected


def behavioral_detection(file=None, **kwargs):
	capture = sniffer.get_capture(file, **kwargs)
	was_detected = False
	previous_arp_type =None
	current_arp_type=None
	concurrent_arp_reply_threshold = 4
	concurrent_arp_reply_count = 0
	request = '1'
	reply = '2'

	for packet in capture:
		if 'arp' in packet:
			current_arp_type = packet.arp.opcode 
			# check if the previous message was a request
			if current_arp_type == reply: #if it's a reply
				if previous_arp_type == request:
					###clear the previous message and move on
					previous_arp_type = current_arp_type
					concurrent_arp_reply_count = 0
				else:
					concurrent_arp_reply_count += 1
					## if it was NOT, there's a problem
					if concurrent_arp_reply_count > concurrent_arp_reply_threshold:
						print("GRATUITOUS ARP DETECTED!!! FLAGGED PACKET:", packet.number)
						was_detected = True
			else:# if it is a request
				previous_arp_type = request
	return was_detected

