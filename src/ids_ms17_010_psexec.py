import sniffer

"""
An IDS system for detecting ms17_010_psexec

Author: Matthew McGlawn
Date: Dec 7 2019
"""

def ms17_010_psexec_signature_detection(file=None, **kwargs):

	"""
	ms17_010_psexec detection function

	Uses the detection of a null session(IPC$) and privilege
	escalation(ADMIN$) within SMB packets.
	"""

    capture = sniffer.get_capture(file, **kwargs)
    for packet in capture:
    	if('SMB' in packet):
    		smb = packet.smb
    		if("path" in dir(smb)):
    			path = smb.path
    			if(("IPC$" in path) or ("ADMIN$" in path)):
    				print("MS_010_psexec detected in packet:" + str(packet.number))

				
if __name__ == "__main__":
	ms17_010_psexec_signature_detection()