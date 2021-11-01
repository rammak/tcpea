

import signal
import sys
import argparse
from tcpea import *


def signal_handler(sig, frame):
    sock.close()
    sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-a', metavar='N', type=str, nargs=1,
                        required=True, help='Server IP address')
    parser.add_argument('-p', metavar='N', type=int, nargs=1,
                        required=True, help='Server port')
    args = parser.parse_args()

    ip = ipv4_address.from_str(args.a[0])

    sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sc.connect(('10.255.255.255', 1))
    own_ip = ipv4_address.from_str(sc.getsockname()[0])
    sc.close()

    # create an INET, raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sock = tcpea(dst_ip_address=ip, dst_port=1234, src_ip_address=own_ip, src_port=random.randint(1024, 0xffff), soc=s)
    sock.connect()
    # wait for connection
    time.sleep(0.2)
    while True:
        something = bytes(input().strip().encode("UTF-8"))
        sock.send(something)


