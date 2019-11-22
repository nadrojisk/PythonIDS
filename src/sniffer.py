import pyshark
import netifaces

"""
Module to sniff packets from a local interface for a
certain peroid of time.

Can also read in pre-exisiting captures and dump the
captures to standard output

Author: Jordan Sosnowski
Date: 11/22/2019
"""


def choose_interface():
    """
    Allows user to select interface based
    on system interfaces
    """
    interfaces = netifaces.interfaces()
    print('Select Interface: ')

    for val, count in enumerate(interfaces):
        print(val, count)

    selection = int(input())

    return interfaces[selection]


def sniff(interface=None, timeout=10, continous=False, out_file=None,):
    """
    Sniffs packet on specified interface, either for a 
    specified number of seconds or forever.

    If interface is not specified local interface will
    be listed. If an outfile is provided the function 
    will save the packet file.

    args:
        interface (str): represents interface to listen on
            defaults -> en0

        out_file (str): represents the file to output saved
        captures to
            defaults -> None

        timeout (int): represents the time to record packets for
            defaults -> 10

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
    if continous:
        capture.sniff_continuously()
    else:
        capture.sniff(timeout=timeout)

    return capture


def read_cap(in_file='/pcaps/mycapture.cap'):
    """ Reads capture file in and returns capture object """

    cap = pyshark.FileCapture(in_file)
    return cap


def dump_cap(capture):
    """ Dumps capture object's packets to standard output """
    for c in capture:
        print(c)
