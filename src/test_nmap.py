import nmap_ids

""" 
Test code for nmap ids

Author: Jordan Sosnowski
Date: Dec 6, 2019
"""


def test_xmas_sig_tp_100():
    # makes sure that running xmas detection returns true
    # if fails, that means our detection is not working as this pcap contains
    # malicious traffic

    # recorded on ubuntu system being scanned by kali via `nmap -sX ip`
    assert nmap_ids.xmas_signature_detection('pcaps/nmap/xmas_ubuntu.pcapng')


def test_xmas_sig_tp_105():
    # makes sure that running xmas detection returns true
    # if fails, that means our detection is not working as this pcap contains
    # malicious traffic

    # recorded on windows system being scanned by kali via `nmap -sX ip`
    assert nmap_ids.xmas_signature_detection('pcaps/nmap/xmas_windows.pcapng')


def test_xmas_sig_tn_100():
    # makes sure that running xmas detection returns false
    # if fails, that means our detection is not working as this pcap contains
    # benign traffic

    # recorded on a mac visiting various websites
    assert not nmap_ids.xmas_signature_detection('pcaps/normal_data2.pcapng')


def test_ack_sig_tp_100():
    # makes sure that running ack detection returns true
    # if fails, that means our detection is not working as this pcap contains
    # malicious traffic

    # recorded on ubuntu system being scanned by kali via `nmap -sA ip`
    assert nmap_ids.ack_signature_detection('pcaps/nmap/ack_ubuntu.pcapng')


def test_ack_sig_tn_100():
    # makes sure that running ack detection returns false
    # if fails, that means our detection is not working as this pcap contains
    # benign traffic

    # recorded on a mac visiting various websites
    assert not nmap_ids.ack_signature_detection('pcaps/normal_data2.pcapng')


def test_ack_sig_tp_100():
    # makes sure that running syn detection returns true
    # if fails, that means our detection is not working as this pcap contains
    # malicious traffic

    # recorded on ubuntu system being scanned by kali via `nmap -sS ip`
    assert nmap_ids.syn_signature_detection('pcaps/nmap/syn_ubuntu.pcapng')


def test_ack_sig_tn_100():
     # makes sure that running syn detection returns false
    # if fails, that means our detection is not working as this pcap contains
    # benign traffic

    # recorded on a mac visiting various websites
    assert not nmap_ids.syn_signature_detection('pcaps/normal_data2.pcapng')
