import nmap_ids


def test_xmas_sig_tp_100():
    assert nmap_ids.xmas_signature_detection('pcaps/nmap/xmas_ubuntu.pcapng')

def test_xmas_sig_tp_105():
    assert nmap_ids.xmas_signature_detection('pcaps/nmap/xmas_windows.pcapng')

def test_xmas_sig_tn_100():
    assert not nmap_ids.xmas_signature_detection('pcaps/normal_data2.pcapng')

def test_ack_sig_tp_100():
    assert nmap_ids.ack_signature_detection('pcaps/nmap/ack_ubuntu.pcapng')

def test_ack_sig_tn_100():
    assert not nmap_ids.ack_signature_detection('pcaps/normal_data2.pcapng')