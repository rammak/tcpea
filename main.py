"""Creates a TCP connection to a server

Usage:
    ./main.py -a 192.168.0.7 -p 1234

Author:
    Rutwij Makwana - 30 Oct 2021
"""

import signal
import sys
import argparse
from tcpea import *


def signal_handler(sig, frame):
    # todo: graceful exit
    sock.close()
    sys.exit(0)


def read_loop():
    while True:
        if incoming := sock.receive():
            print(incoming.decode(encoding="UTF-8"), end="")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('-a', metavar='N', type=str, nargs=1,
                        required=True, help='Remote IP address')
    parser.add_argument('-p', metavar='N', type=int, nargs=1,
                        required=True, help='Remote port')
    parser.add_argument('-l', default=None, action="store_true", help='Listen/create server')
    args = parser.parse_args()
    # print(args)

    ip = ipv4_address.from_str(args.a[0])

    sc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sc.connect(('10.255.255.255', 1))
    own_ip = ipv4_address.from_str(sc.getsockname()[0])
    sc.close()

    sock = tcpea(src_ip_address=own_ip)

    read_thread = threading.Thread(target=read_loop)

    if not args.l:
        sock.connect(dst_ip_address=ip, dst_port=args.p[0], src_port=random.randint(1024, 0xffff))
        # wait for connection
        time.sleep(0.2)
        read_thread.start()
        while True:
            something = bytes(input().strip().encode("UTF-8"))
            sock.send(something)
    else:
        sock.listen(port=args.p[0])
        while True:
            if sock.accept():
                read_thread.start()
                while True:
                    something = bytes(input().strip().encode("UTF-8"))
                    sock.send(something)



