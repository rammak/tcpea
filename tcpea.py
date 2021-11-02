"""tcpea core classes

Author:
    Rutwij Makwana - 31 Oct 2021
"""

import random
import enum
import queue
import threading
import time

from tcpea_common import *


class tcp_state(enum.Enum):
    CLOSED = 0
    LISTEN = 1
    SYN_SENT = 2
    SYN_RECEIVED = 3
    ESTABLISHED = 4
    FIN_WAIT_1 = 5
    FIN_WAIT_2 = 6
    CLOSE_WAIT = 7
    CLOSING = 8
    LAST_ACK = 9
    TIME_WAIT = 10


class app_state(enum.Enum):
    CLOSE = 0
    ACTIVE_OPEN = 1
    PASSIVE_OPEN = 2
    LISTEN = 3

class REMOTE_CLOSED(Exception):
    pass

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
               pac_id: int = random.randint(0, 0xffff), fl_df: bool = False, ttl: int = 128):
        header = bytearray([0x45, 0x00, (len(payload) + 20) >> 8, (len(payload) + 20) & 0xff, (pac_id >> 8),
                            (pac_id & 0xff), (fl_df << 6), 0x00, ttl, proto, 0x00, 0x00,
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

    def __init__(self):
        pass

    @classmethod
    def from_raw(cls, data: bytes):
        out = tcp_packet()
        # print("TCP packet length ", len(data))
        out.src_port = data[0] << 8 | data[1]
        out.dst_port = data[2] << 8 | data[3]
        out.seq_no = data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7]
        out.ack_no = data[8] << 24 | data[9] << 16 | data[10] << 8 | data[11]
        out.fl_ack = bool(data[13] & 0b00010000)
        out.fl_push = bool(data[13] & 0b00001000)
        out.fl_rst = bool(data[13] & 0b00000100)
        out.fl_syn = bool(data[13] & 0b00000010)
        out.fl_fin = bool(data[13] & 0b00000001)
        out.window = data[14] << 8 | data[15]
        out.checksum = data[16] << 8 | data[17]
        out.offset = ((data[12] >> 4) * 4)
        out.payload = data[out.offset:]
        # if there are options
        if out.offset > 20:
            i = 20
            while i < out.offset:
                if data[i] == 1:  # NOOP option
                    i += 1
                    continue
                if data[i] == 2:  # MSS option
                    out.opt_mss = data[i + 2] << 8 | data[i + 3]
                elif data[i] == 3:  # WSCALE option
                    out.opt_wscale = data[i + 2]
                i += data[i + 1]
        return out

    @classmethod
    def to_raw(cls, src_ip: ipv4_address, dst_ip: ipv4_address, src_port: int, dst_port: int, seq_no: int, ack_no: int,
               window: int, payload: bytes, fl_ack: bool = False, fl_syn: bool = False, fl_rst: bool = False,
               fl_fin: bool = False, fl_push: bool = False, opt_mss=None, opt_wscale=None):
        print("hsh ", src_ip.to_str(), dst_ip.to_str())
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
                            header_length << 4, flags, window >> 8, window & 0xff, 0x00, 0x00,
                            0x00, 0x00]) + bytearray(options)
        pseudo_header = bytearray(
            src_ip.ip + dst_ip.ip + bytearray([0x00, 0x06, (len(payload) + (header_length * 4)) >> 8,
                                               (len(payload) + (header_length * 4)) & 0xff]))
        # print("pseudo ")
        # for i in range(len(pseudo_header)):
        #     print(hex(pseudo_header[i]), end=" ")
        # print()
        cksm = ipv4_checksum(pseudo_header + header + payload)
        # print(hex(cksm))
        header[16] = cksm >> 8
        header[17] = cksm & 0xff
        return header + payload


class tcpea:
    server: bool = False
    state: tcp_state = tcp_state.CLOSED
    app: app_state = app_state.CLOSE
    dst_ip: ipv4_address = None
    dst_port: int = None
    src_ip: ipv4_address = None
    src_port: int = None
    soc: socket.socket = None
    seq: int = random.randint(0, 0xffffffff)
    ack: int = 0
    s_buffer: queue.Queue = None
    r_buffer: queue.Queue = None
    remote_conn: bool = False

    __th: threading.Thread = None
    __tw_th: threading.Thread = None
    __l: threading.Lock = threading.Lock()
    __l1: threading.Lock = threading.Lock()

    def __init__(self, src_ip_address: ipv4_address, send_buffer: int = 3000, receive_buffer: int = 3000):
        self.src_ip = src_ip_address
        self.s_buffer = queue.Queue(send_buffer)
        self.r_buffer = queue.Queue(receive_buffer)
        self.__th = threading.Thread(target=self.loop)
        self.__tw_th = threading.Thread(target=self.__time_wait)

        self.soc = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        self.soc.settimeout(1)

    def __del__(self):
        if self.soc is not None:
            self.soc.close()

    def bind(self, port: int):
        self.src_port = port

    def connect(self, dst_ip_address: ipv4_address, dst_port: int, src_port: int):
        self.dst_ip = dst_ip_address
        self.dst_port = dst_port
        self.src_port = src_port
        if not self.__th.is_alive():
            self.__th.start()
        self.__l.acquire()
        self.app = app_state.ACTIVE_OPEN
        try:
            self.__send_flag(fl_syn=True)
            self.app = app_state.ACTIVE_OPEN
            self.__goto_state(tcp_state.SYN_SENT)
        finally:
            self.__l.release()

    def send(self, data: bytes):
        if self.state == tcp_state.ESTABLISHED:
            self.s_buffer.put(data)
            return len(data)
        else:
            return 0

    def receive(self):
        if self.r_buffer.empty() is False:
            return self.r_buffer.get()
        else:
            return False

    def close(self):
        self.__l.acquire()
        try:
            if self.state == tcp_state.ESTABLISHED:
                self.app = app_state.CLOSE
        finally:
            self.__l.release()

    def listen(self, port: int):
        self.server = True
        self.dst_ip = ipv4_address.from_str("0.0.0.0")
        self.src_port = port
        self.app = app_state.LISTEN
        if self.state == tcp_state.CLOSED:
            self.__goto_state(tcp_state.LISTEN)
            if not self.__th.is_alive():
                self.__th.start()
            self.__l.acquire()
            return True
        else:
            return False

    def accept(self):
        if self.remote_conn:
            return self.dst_ip, self.dst_port
        else:
            return None

    def loop(self):
        while True:
            r = receive_from(self.soc, self.dst_ip)

            # if application has closed, close connection gracefully
            if self.app == app_state.CLOSE and self.state == tcp_state.TIME_WAIT or self.state == tcp_state.LAST_ACK:
                return
            # filter empty returns because of a timeout
            if len(r) == 0:
                continue

            rp = tcp_packet.from_raw(r[20:])
            # todo: check for checksum
            if rp.dst_port != self.src_port:
                # print("Wrong port ", rp.dst_port, self.src_port)
                continue

            # --------TCP STATE MACHINE----------
            if self.state == tcp_state.CLOSED:
                # todo: this send throws permission denied
                # self.__send_reset()
                continue
                # add passive open

            elif self.state == tcp_state.LISTEN:
                if rp.fl_syn:
                    ip_pac = ip_packet.from_raw(r)
                    self.dst_ip = ip_pac.src_ip
                    self.dst_port = rp.src_port
                    print(self.src_ip, self.src_port, self.dst_ip, self.dst_port)
                    self.seq = random.randint(0, 0xffffffff)
                    self.ack = rp.seq_no + 1
                    self.__send_flag(fl_syn=True, fl_ack=True)
                    self.app = app_state.PASSIVE_OPEN
                    self.__goto_state(tcp_state.SYN_RECEIVED)

            elif self.state == tcp_state.SYN_RECEIVED:
                if self.app == app_state.CLOSE:
                    self.__send_flag(fl_fin=True, fl_ack=True)
                elif rp.fl_rst:
                    self.__goto_state(tcp_state.LISTEN)
                elif rp.fl_ack and rp.ack_no == self.seq + 1:
                    self.__goto_state(tcp_state.ESTABLISHED)
                    self.remote_conn = True
                else:
                    self.__goto_state(tcp_state.CLOSED)
                    self.__send_reset()
                    break

            elif self.state == tcp_state.SYN_SENT:
                if self.app == app_state.CLOSE:
                    self.__goto_state(tcp_state.CLOSED)
                    self.__send_reset()
                elif (rp.fl_syn and rp.fl_ack) and rp.ack_no == self.seq + 1:
                    self.ack = rp.seq_no + 1
                    self.seq += 1
                    self.__send_flag(fl_ack=True)
                    self.__goto_state(tcp_state.ESTABLISHED)
                elif rp.fl_syn:
                    self.ack = rp.seq_no + 1
                    self.seq += 1
                    self.__send_flag(fl_syn=True, fl_ack=True)
                    self.__goto_state(tcp_state.SYN_RECEIVED)
                else:
                    self.__goto_state(tcp_state.CLOSED)
                    self.__send_reset()
                    break

            elif self.state == tcp_state.ESTABLISHED:
                # self.dst_ip = rp.src_ip
                # if rp.ack_no != self.seq:
                #     # todo: handle retransmissions here
                #     self.__send_reset()
                #     self.__goto_state(tcp_state.CLOSED)
                #     break
                if rp.fl_rst:
                    self.__goto_state(tcp_state.CLOSED)
                    break

                # passive close
                elif rp.fl_fin:
                    self.ack += 1
                    self.__send_flag(fl_ack=True)
                    self.__goto_state(tcp_state.CLOSE_WAIT)

                # active close
                elif self.app == app_state.CLOSE:
                    self.__send_flag(fl_fin=True, fl_ack=True)
                    self.__goto_state(tcp_state.FIN_WAIT_1)

                elif rp.ack_no == self.seq + 1:
                    self.ack += len(rp.payload)
                    if len(rp.payload) != 0:
                        self.__send_flag(fl_ack=True)
                    self.r_buffer.put(rp.payload)
                    # print(rp.payload.decode(encoding="UTF-8"), end="")
                else:
                    self.__goto_state(tcp_state.CLOSED)
                    self.__send_reset()
                    break

                if not self.s_buffer.empty():
                    print("S buffer not empty")
                    self.ack = rp.seq_no + 1
                    data_tcp = tcp_packet.to_raw(src_ip=self.src_ip, src_port=self.src_port, dst_ip=self.dst_ip,
                                                 dst_port=self.dst_port, seq_no=self.seq, ack_no=self.ack,
                                                 window=0xfaf0,
                                                 fl_ack=True, payload=self.s_buffer.get())
                    send_to(self.soc, ip=self.dst_ip, port=self.dst_port, data=data_tcp)

            elif self.state == tcp_state.FIN_WAIT_1:
                if rp.fl_fin:
                    self.ack += 1
                    self.__send_flag(fl_ack=True)
                    self.__goto_state(tcp_state.CLOSING)
                elif rp.fl_ack:
                    # wait for the remote app to close
                    self.__goto_state(tcp_state.FIN_WAIT_2)
                elif rp.fl_ack and rp.fl_fin:
                    self.ack += 1
                    self.__send_flag(fl_ack=True)
                    self.__goto_state(tcp_state.TIME_WAIT)
                else:
                    self.__goto_state(tcp_state.CLOSED)
                    self.__send_reset()
                    break

            elif self.state == tcp_state.FIN_WAIT_2:
                if rp.fl_fin:
                    self.seq = rp.ack_no
                    self.ack += 1
                    self.__send_flag(fl_ack=True)
                    self.__goto_state(tcp_state.TIME_WAIT)
                else:
                    self.__goto_state(tcp_state.CLOSED)
                    self.__send_reset()
                    break

            elif self.state == tcp_state.CLOSING:
                if rp.fl_ack:
                    self.__goto_state(tcp_state.TIME_WAIT)
                else:
                    self.__goto_state(tcp_state.CLOSED)
                    self.__send_reset()
                    break

            elif self.state == tcp_state.TIME_WAIT:
                break

            else:
                self.__goto_state(tcp_state.CLOSED)
                self.__send_reset()

    def __send_reset(self):
        self.__send_flag(fl_rst=True)

    def __send_flag(self, fl_ack: bool = False, fl_push: bool = False, fl_rst=False, fl_syn=False,
                    fl_fin: bool = False):
        # print("Sending flag")
        # if fl_fin:
        #     self.seq += 1
        print("flg ", self.src_ip.to_str(), self.dst_ip.to_str())
        fl_tcp = tcp_packet.to_raw(src_ip=self.src_ip, src_port=self.src_port, dst_ip=self.dst_ip,
                                   dst_port=self.dst_port, seq_no=self.seq, ack_no=self.ack, window=0xfaf0,
                                   fl_rst=fl_rst, fl_ack=fl_ack, fl_push=fl_push, fl_syn=fl_syn, fl_fin=fl_fin,
                                   payload=bytes())
        send_to(self.soc, ip=self.dst_ip, port=self.dst_port, data=fl_tcp)

    def __check_valid(self, pac: tcp_packet):
        # todo: check packet validity
        return True

    def __goto_state(self, state: tcp_state):
        self.__l1.acquire()
        try:
            print("Transitioning to ", state)
            if state == tcp_state.TIME_WAIT:
                self.__tw_th.start()
            else:
                self.state = state
        finally:
            self.__l1.release()

    def __time_wait(self):
        # todo: implement 2MSL
        time.sleep(2)
        self.__goto_state(tcp_state.CLOSED)
        # workaround to stop the loop thread
        # send_to(self.soc, self.src_ip, 0, bytes())
        self.soc.close()
        raise REMOTE_CLOSED
