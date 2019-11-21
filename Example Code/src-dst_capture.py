#Barebones Packet Sniffer
#continuously pulls packets, and identifies their source and destination
#	can be used to check if the wireless card is in promiscuous mode or not

import pyshark
import sys

if __name__ == "__main__":
    iface = ""
    if len(sys.argv) >= 2:
        iface=sys.argv[1]
    if len(sys.argv) > 2:
        for i in sys.argv[2:]:
            iface+=" {}".format(i)
            if "'" in i:
                iface = iface [1:-1]
                break

    print("capture on i-face ",iface)
    capture = pyshark.LiveCapture(interface=iface) #set up the capture device as a live capture with the provided wifi interface
    for packet in capture.sniff_continuously():
        print("src:",packet.ip.src,'\tdst:',packet.ip.dst)
    