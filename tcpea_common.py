"""tcpea helper functions

Author:
    Rutwij Makwana - 31 Oct 2021
"""

import socket
import queue
import threading
import enum


class ether_type(enum.IntEnum):
    IPV4 = 0x0800
    ARP = 0x0806


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
            return ipv4_address(bytes([int(i) for i in ips]))

    def __repr__(self):
        return self.to_str()

    def to_str(self):
        return str(self.ip[0]) + "." + str(self.ip[1]) + "." + str(self.ip[2]) + "." + str(self.ip[3])


class eth_address:
    eth: bytes = None

    def __init__(self, mac_address: bytes):
        self.eth = mac_address

    @classmethod
    def from_str(cls, mac_str: str):
        mac = mac_str.split(":")
        if len(mac) != 6:
            return None
        else:
            a: list = []
            for i in mac:
                a.append(int("0x" + i, 0))
            return eth_address(bytes(a))

    def __repr__(self):
        return self.to_str()

    def to_str(self):
        return format(self.eth[0], '02x') + ":" + format(self.eth[1], '02x') + ":" + format(self.eth[2], '02x') + ":" \
               + format(self.eth[3], '02x') + ":" + format(self.eth[4], '02x') + ":" + format(self.eth[5], '02x')


class eth_frame:
    src_mac: eth_address = None
    dst_mac: eth_address = None
    proto: int = None
    payload: bytes = None

    def __init__(self, src_mac: eth_address, dst_mac: eth_address, proto: ether_type, payload: bytes):
        self.src_mac: eth_address = src_mac
        self.dst_mac: eth_address = dst_mac
        self.proto: ether_type = proto
        self.payload: bytes = payload

    @classmethod
    def to_raw(cls, src_mac: eth_address, dst_mac: eth_address, proto: ether_type, payload: bytes):
        return bytes(dst_mac.eth + src_mac.eth + bytes([int(proto) >> 8, int(proto) & 0xff]) + payload)

    @classmethod
    def from_raw(cls, data: bytes):
        return eth_frame(dst_mac=eth_address(data[0:6]), src_mac=eth_address(data[6:12]),
                         proto=ether_type(data[12] << 8 | data[13]), payload=data[14:])


class ethernet:
    mac: eth_address = None
    interface: str = None
    protos: list = []
    running: bool = True
    buffer: int = 0

    __rq: queue.Queue = None
    __sq: queue.Queue = None
    __soc: socket.socket = None
    __rt: threading.Thread = None
    __st: threading.Thread = None

    def __init__(self, mac_address: eth_address, interface: str, buffer: int = 250):
        print("in init")
        self.mac = mac_address
        self.interface = interface
        self.buffer = buffer
        self.__rq = queue.Queue(buffer)
        self.__sq = queue.Queue(buffer)

        self.__soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.__soc.bind((self.interface, 0))
        self.__soc.settimeout(0.1)

        self.__rt = threading.Thread(target=self.__read_loop)
        self.__rt.start()
        self.__st = threading.Thread(target=self.__send_loop)
        self.__st.start()

    def __del__(self):
        self.__soc.close()

    def register_protocol(self, proto: ether_type):
        self.protos.append(proto)

    def deregister_protocol(self, proto: ether_type):
        self.protos.remove(proto)

    def receive(self):
        if not self.__rq.empty():
            return self.__rq.get()
        else:
            return None

    def send(self, data: bytes):
        self.__sq.put(data)

    def __read_loop(self):
        while self.running:
            try:
                frame = self.__soc.recv(2000)
                # print_packet(frame)
                # print(frame[:6] == self.mac.eth)
                # print(ether_type(frame[12] << 8 | frame[13]) in self.protos, ether_type(frame[12] << 8 | frame[13]), self.protos)
                # e_frame = eth_frame.from_raw(frame)
                if frame[:6] == bytes([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]) or \
                        (frame[:6] == self.mac.eth and (ether_type(frame[12] << 8 | frame[13]) in self.protos)):
                    # push the frame with its protocol
                    # print("Pushing one frame ", (frame[12] << 8 | frame[13]))
                    self.__rq.put((frame, ether_type(frame[12] << 8 | frame[13])))
            except socket.timeout:
                pass

    def __send_loop(self):
        while self.running:
            if not self.__sq.empty():
                self.__soc.send(self.__sq.get())



# legacy
def send_to(soc: socket.socket, ip: ipv4_address, port: int, data: bytes):
    return soc.sendto(data, (ip.to_str(), port))

# legacy
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

