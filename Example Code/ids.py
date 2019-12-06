import sniffer

"""
An IDS system for detecting nmap recon, arp poisoning, responder, and eternal blue
"""

def main():

	host_in_question = ""
	previous_arp_type = ""
	concurrent_arp_req_count = 0
	arp_req_count = 0
	arp_resp_count = 0
	arp_req_threshold = 10
	concurrent_arp_reply_threshold = 4
	concurrent_arp_reply_count = 0

	interface=sniffer.choose_interface()
	capture = sniffer.sniff(interface="Wi-Fi", timeout=0)
	for packet in capture:
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

		if 'arp' in packet: 
			print("ARP packet")
			if packet.arp.opcode == 1: #if the arp packet is an arp request
				if host_in_question == "": #ettercap 1
					host_in_question = packet.eth.src # set first MAC SRC address for ARP messages
				elif host_in_question == packet.eth.src: # if the current mac equals the previous mac
					concurrent_arp_req_count += 1
				else:
					host_in_question = packet.eth.src
					concurrent_arp_req_count = 0
				if concurrent_arp_req_count >= arp_req_threshold: # if the number of concurrent arp_requests with the same src exceeds our threshold there's a problem
					print("ARP POISONING DETECTED")

			if packet.arp.duplicate-address-detected: #ettercap 2
				print("ARP POISONING DETECTED")

			#for every request, assuming there is a host on the ip, there should be a reply a = b
			#for every request for a non-existent host, the should be no reply a > b
			#for every reply, there should be a request b = a
			# therefore, if there is a reply without a request, we know something is wrong b > a

			#get the type of arp packet
			current_arp_type = packet.arp.opcode
			#if it's a reply, 
			# check if the previous message was a request
			if current_arp_type == 2:
			##if the previous message was a request, you're ok
				if previous_arp_type == 1:
					###clear the previous message and move on
					previous_arp_type = current_arp_type
					concurrent_arp_reply_count = 0
				else:
					concurrent_arp_reply_count += 1
					## if it was NOT, there's a problem
					if concurrent_arp_reply_count > concurrent_arp_reply_threshold:
						print("ARP POISONING DETECTED")
				# if it is a request
			if current_arp_type == 1:
				previous_arp_type = 1


			




if __name__ == "__main__":
	main()