# Executive summary

For this project we were tasked with producing a Python based intrusion detection system (IDS).
Our IDS is a host based IDS, by that we mean it is ran on each host on the network.
Only the host can see traffic to or from itself.
The IDS implementation protects against NMAP SYN Scans, ACK Scans, and XMAS Scans, Ettercap, Responder, CVE-2017-010.
We also use various types of detection systems to protect against attacks there are 4 covered: behavioral, anomaly, signature, and heuristic.

# Introduction

## I. Problem Description


## II. Definition of Terms

### 1. Intrusion Detection System

Software or device that analyzes network traffic for malicious activity.
Malicious activity is usually flagged, with the administrator of the network being notified of the incident.
IDS systems can also be configured to stop detected intrusions.

### 2. Host Based Intrusion Detection System

A host based IDS is an intrusion detection system that is run on the computers on the network.
The opposite of a host based IDS is a network based IDS where the IDS is instead run on the network switches / routers.
The downside for a host based IDS is, for a switched network, an IDS will only be able to see traffic destined to or from the host it is running on.
Since it a switched network the switch will only forward packets to the intended ports.
If it was a hub network, or the switch was configured to have a trunk then a host based IDS would be able to see all the traffic on the network.

### 3. Behavior IDS

Analyzes traffic using a *known baseline*.
If the traffic is not close to this baseline the traffic will be flagged.
An example would be if a network is known to only have FTP traffic but for some reason there is now packets using SSH and SFTP traffic it should be flagged.
Of course in this example a user could have spun up a box that uses SSH or SFTP but since the baseline is used to seeing only FTP it is abnormal traffic.

### 4. Anomaly IDS

Attempts to find abnormal *protocol* activity.
Protocols adhere to strict guidelines, most are defined in RFCs.
If for instance, there is traffic on a network that shows a protocol not adhering to its normal activity it should be flagged.
This is different from a behavior IDS because it is focused on *protocol* activity while behavior is focused on looking at what is *normal* for a network.

### 5. Signature IDS

Searches network traffic for **specific patterns**.
Malicious traffic usually has telltale signs, and if these *signs* are seen in packets they should be flagged as malicious.
If for instance it is known that a recent strain of a popular malware communicate with a server **www.bad_malware.com** on port **8080** then any packets destined to this address and port should be flagged.

### 6. Heuristic IDS

Uses algorithms or *simple rules* to determine compromise.
Can combine signature, anomaly, and behavior tactics.
For example it would be odd for a single IP to scan multiple different ports with a payload of zero data.
A simple rule could check and see if a unique IP has more than 20 unique destination ports plus using the signature of length zero data packets.
If this rule is triggered one can assume it is malicious.

### 7. NMAP

A free and open-source network scanner and mapper tool used both by information security experts and malicious users.
NMAP provides a huge number of features for scanning and probing networks.

### 8. Ettercap

### 9. Responder

### 10. Metasploit

### 11. CVE-2017-010

# Methods

## I. Code Walkthrough

## II. Screenshots



# Recommendations


# Conclusion


# Appendix

## I. Sniffer Code

## II. IDS Code

## III. NMAP IDS Code

## IV. Ettercap IDS Code

## V. Responder IDS Code

## VI. CVE-2017-010 IDS Code