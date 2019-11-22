import src.sniffer as sniffer

cap = sniffer.sniff('en0')

sniffer.dump_cap(cap)
