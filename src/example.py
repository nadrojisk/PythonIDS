import sniffer as sniffer

cap = sniffer._sniff(continuous=True)

for p in cap:
    p.pretty_print()
