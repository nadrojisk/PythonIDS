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
