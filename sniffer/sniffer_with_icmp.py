import ipaddress
import socket

# host su cui rimanere in ascolto
import struct
import sys

HOST = '192.168.1.52'


class IP:
    def __init__(self, buff=None):
        header = struct.unpack('<BBHHHBBH4s4s', buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # indirizzzi IP in formato leggibile
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # mappatura dei protocolli
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(f"{e} No protocol for {self.protocol_num}")
            self.protocol = str(self.protocol_num)


class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


def sniff(host):
    # creiamo un raw socket, lo colleghiamo all'interfaccia pubblica
    socket_protocol = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))

    # includiamo le intestazioni IP nella cattura
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # lettura del pacchetto
            raw_buffer = sniffer.recvfrom(65535)[0]
            # creazione di un pacchetto IP dai primi 20 byte
            ip_header = IP(raw_buffer[0:20])
            if ip_header.protocol == "ICMP":
                print(f'Protocol: {ip_header.protocol} {ip_header.src_address} --> {ip_header.dst_address}')
                print(f'Version: {ip_header.ver}')
                print(f'Header Length: {ip_header.ihl}\tTTL: {ip_header.ttl}')

                # calcoliamo dove il pacchetto ICMP inizia
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                icmp_header = ICMP(buf)
                print(f'ICMP -> Type {icmp_header.type} Code {icmp_header.code}\n')

    except KeyboardInterrupt:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = HOST
    sniff(host)
