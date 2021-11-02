"""tcpea helper functions

Author:
    Rutwij Makwana - 31 Oct 2021
"""

import socket


def print_packet(data: bytes):
    print("Packet length: ", len(data), end=" ")
    for i in range(len(data)):
        print(hex(data[i]), end=" ")
    print()


# Calculate IP 16-bit checksum
def ipv4_checksum(data: bytes):
    # print("Checksum data length: ", len(data))
    check = 0                                           # final checksum
    # append empty byte to make data length even
    if len(data) % 2 == 1:
        data = data + bytes([0])
    # print("Checksum data length after: ", len(data))
    for i in range(0, len(data), 2):
        check += (data[i] << 8) + data[i+1]             # add bytes
        check = (check & 0xffff) + (check >> 16)        # add carry
    return 0xffff - check                               # 1's complement


class ipv4_address:
    ip: bytes = None

    def __init__(self, ip_address: bytes):
        self.ip = ip_address

    @classmethod
    def from_str(cls, ip_str: str):
        ips = ip_str.split(".")
        if len(ips) != 4:
            return None
        else:
            return cls(bytes([int(i) for i in ips]))

    @classmethod
    def from_ip(cls, ip_list: bytes):
        if len(ip_list) != 4:
            return None
        else:
            return cls(ip_list)

    def __repr__(self):
        return self.to_str()

    def to_str(self):
        return str(self.ip[0]) + "." + str(self.ip[1]) + "." + str(self.ip[2]) + "." + str(self.ip[3])


def send_to(soc: socket.socket, ip: ipv4_address, port: int, data: bytes):
    return soc.sendto(data, (ip.to_str(), port))


def receive_from(soc: socket.socket, ip: ipv4_address):
    while True:
        try:
            pac = soc.recvfrom(65565)
            # print(pac[1])
            if pac[1][0] == ip.to_str() or ip.to_str() == "0.0.0.0":
                # print("returning ", pac)
                return pac[0]
        except socket.timeout:
            pass
