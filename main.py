# https://www.binarytides.com/python-packet-sniffer-code-linux/
# sudo iptables -A OUTPUT -p tcp --sport 6 --tcp-flags RST RST -j DROP
# netstat -anp --raw
# ss -tulw

import random
import socket
import argparse
import unittest
import os
import time


def print_packet(data: bytes):
    for i in range(len(data)):
        print(hex(data[i]), end=" ")
    print()


# Calculate IP 16-bit checksum
def ipv4_checksum(data: bytes):
    check = 0                                           # final checksum
    # append empty byte to make data length even
    if len(data) % 2 == 1:
        data = data + bytes(0x00)
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


class ip_packet:
    src_ip: ipv4_address = None
    dst_ip: ipv4_address = None
    proto: int = 0
    payload: bytes = None

    def __init__(self, src_address: ipv4_address, dst_address: ipv4_address, payload: bytes, proto=6):
        self.src_ip = src_address
        self.dst_ip = dst_address
        self.proto = proto
        self.payload = payload

    @classmethod
    def from_raw(cls, raw_packet: bytes):
        return cls(ipv4_address.from_ip(raw_packet[12:16]), ipv4_address.from_ip(raw_packet[16:20]), raw_packet[20:])

    @classmethod
    def to_raw(cls, src_address: ipv4_address, dst_address: ipv4_address, payload: bytes, proto: int = 6,
               id: int = random.randint(0, 0xffff), fl_df: bool = False, ttl: int = 128):
        header = bytearray([0x45, 0x00, (len(payload)+20) >> 8, (len(payload)+20) & 0xff, (id >> 8), (id & 0xff),
                            (fl_df << 6), 0x00, ttl, proto, 0x00, 0x00,
                            src_address.ip[0], src_address.ip[1], src_address.ip[2], src_address.ip[3],
                            dst_address.ip[0], dst_address.ip[1], dst_address.ip[2], dst_address.ip[3]])
        cksm = ipv4_checksum(header)
        header[10] = cksm >> 8
        header[11] = cksm & 0x00ff
        return header + payload

class tcp_packet:
    src_ip: ipv4_address = None
    src_port: int = None
    dst_ip: ipv4_address = None
    dst_port: int = None
    seq_no: int = None
    ack_no: int = None
    window: int = None
    payload: bytes = None
    fl_ack: bool = None
    fl_syn: bool = None
    fl_rst: bool = None
    fl_fin: bool = None
    fl_push: bool = None
    checksum: int = None
    offset: int = None
    opt_mss: int = None
    opt_wscale: int = None

    @classmethod
    def from_raw(cls, data: bytes):
        cls.src_port = data[0] << 8 | data[1]
        cls.dst_port = data[2] << 8 | data[3]
        cls.seq_no = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7]
        cls.ack_no = data[8] << 24 | data[9] << 16 | data[10] << 8 | data[11]
        cls.fl_ack = bool(data[13] & 0b00010000)
        cls.fl_push = bool(data[13] & 0b00001000)
        cls.fl_rst = bool(data[13] & 0b00000100)
        cls.fl_syn = bool(data[13] & 0b00000010)
        cls.fl_fin = bool(data[13] & 0b00000001)
        cls.window = data[14] << 8 | data[15]
        cls.checksum = data[16] << 8 | data[17]
        cls.offset = ((data[12] >> 4)*4)
        cls.payload = data[cls.offset:]
        # if there are options
        if cls.offset > 20:
            i = 20
            while i < cls.offset:
                if data[i] == 1:      # NOOP option
                    i += 1
                    continue
                if data[i] == 2:        # MSS option
                    cls.opt_mss = data[i+2] << 8 | data[i+3]
                elif data[i] == 3:      # WSCALE option
                    cls.opt_wscale = data[i+2]
                i += data[i+1]
        return cls

    @classmethod
    def to_raw(cls, src_ip: ipv4_address, dst_ip: ipv4_address, src_port: int, dst_port: int, seq_no: int, ack_no: int,
               window: int, payload: bytes, fl_ack: bool = False, fl_syn: bool = False, fl_rst: bool = False,
               fl_fin: bool = False, fl_push: bool = False, opt_mss=None, opt_wscale=None, proto: int = 6):
        header_length = 5
        options = []
        if opt_wscale is not None:
            header_length += 1
            options += [0x03, 0x03, opt_wscale, 0x01]
        if opt_mss is not None:
            header_length += 1
            options += [0x02, 0x04, opt_mss >> 8, opt_mss & 0xff]
        flags = (fl_ack << 4) | (fl_push << 3) | (fl_rst << 2) | (fl_syn << 1) | fl_fin
        header = bytearray([src_port >> 8, src_port & 0xff, dst_port >> 8, dst_port & 0xff,
                            seq_no >> 24, (seq_no >> 16) & 0xff, (seq_no >> 8) & 0xff, seq_no & 0xff,
                            ack_no >> 24, (ack_no >> 16) & 0xff, (ack_no >> 8) & 0xff, ack_no & 0xff,
                            header_length << 4, flags, window >> 8, window & 0xff, 0x00, 0x00, 0x00, 0x00])\
                 + bytearray(options)
        pseudo_header = bytearray(src_ip.ip + dst_ip.ip + bytearray([0x00, 0x06, (len(payload)+(header_length*4)) >> 8,
                                                                     (len(payload)+(header_length*4)) & 0xff]))
        # print("pseudo ")
        # for i in range(len(pseudo_header)):
        #     print(hex(pseudo_header[i]), end=" ")
        # print()
        cksm = ipv4_checksum(pseudo_header + header + payload)
        print(hex(cksm))
        header[16] = cksm >> 8
        header[17] = cksm & 0xff
        return header + payload


class tcpea:

    dst_ip: ipv4_address = None
    dst_port: int = None
    src_ip: ipv4_address = None
    src_port: int = None
    soc: socket.socket = None
    seq: int = random.randint(0, 0xffffffff)
    ack: int = 0

    def __init__(self, dst_ip_address: ipv4_address, dst_port: int, src_ip_address: ipv4_address, src_port: int,
                 soc: socket.socket):
        self.dst_ip = dst_ip_address
        self.dst_port = dst_port
        self.src_ip = src_ip_address
        self.src_port = src_port
        self.soc = soc

    def connect(self):
        syn_tcp = tcp_packet.to_raw(src_ip=self.src_ip, src_port=self.src_port, dst_ip=self.dst_ip,
                                    dst_port=self.dst_port, seq_no=self.seq, ack_no=self.ack, window=0xfaf0,
                                    fl_syn=True, payload=bytes(), opt_mss=1460, opt_wscale=7)
        print(send_to(self.soc, ip=self.dst_ip, port=self.dst_port, data=syn_tcp))
        while True:
            syn_ack_raw = receive_from(self.soc, self.dst_ip, self.dst_port)
            syn_ack = tcp_packet.from_raw(syn_ack_raw[20:])
            # if we find the correct packet
            if (syn_ack.src_port == self.dst_port) & syn_ack.fl_syn & syn_ack.fl_ack:
                self.seq += 1
                self.ack = syn_ack.seq_no + 1
                break
        # print_packet(syn_ack_raw)
        # print(syn_ack.fl_syn, syn_ack.fl_ack, syn_ack.seq_no, syn_ack.ack_no)
        print("Found our packet")
        fin_tcp = tcp_packet.to_raw(src_ip=self.src_ip, src_port=self.src_port, dst_ip=self.dst_ip,
                                    dst_port=self.dst_port, seq_no=self.seq, ack_no=self.ack, window=0xfaf0,
                                    fl_ack=True, payload=bytes())
        send_to(self.soc, ip=self.dst_ip, port=self.dst_port, data=fin_tcp)


    def listen(self):
        pass


class ipea:
    pass


def send_to(soc: socket.socket, ip: ipv4_address, port: int, data: bytes):
    return soc.sendto(data, (ip.to_str(), port))


def receive_from(soc: socket.socket, ip: ipv4_address, port: int):
    while True:
        pac = soc.recvfrom(65565)
        # print(pac)
        if pac[1][0] == ip.to_str():
            # print("Raw ")
            # print_packet(pac[0])
            return pac[0]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-a', metavar='N', type=str, nargs=1,
                        required=True, help='Server IP address')
    parser.add_argument('-p', metavar='N', type=int, nargs=1,
                        required=True, help='Server port')
    args = parser.parse_args()
    print(args.a, args.p)

    ip = ipv4_address.from_str(args.a[0])
    print(ip.to_str())

    sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sc.connect(('10.255.255.255', 1))
    own_ip = ipv4_address.from_str(sc.getsockname()[0])
    sc.close()
    print("Own ip - ", own_ip.to_str())


    #create an INET, raw socket
    # ps = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ps.bind((own_ip.to_str(), 2345))
    # ps.listen()
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.bind((own_ip.to_str(), 2345))
    # s.connect((ip.to_str(), 1234))
    # time.sleep(10)
    sock = tcpea(dst_ip_address=ip, dst_port=1234, src_ip_address=own_ip, src_port=6, soc=s)

    packet = bytes([0x08, 0x00, 0xcc, 0x97, 0x00, 0x04,
                  0x00, 0x01, 0x63, 0xc1, 0x7e, 0x61, 0x00, 0x00,
                  0x00, 0x00, 0x86, 0x6d, 0x04, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                  0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                  0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
                  0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                  0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                  0x36, 0x37])

    # # receive a packet
    while True:
        # print()
        # print(send_to(s, ipv4_address.from_str("192.168.0.7"), 0, packet))
        #
        # a = receive_from(s, ipv4_address.from_str("192.168.0.7"), 0)
        # print(a)
        sock.connect()
        time.sleep(0.5)
        # p = ip_packet.from_raw(a[0])
        # print(p.src_ip)


