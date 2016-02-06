from __future__ import unicode_literals, print_function, division

import signal
import sys

from pcapparser.parse_pcap import get_tcpconn
from pcapparser import config
from pcapparser.httpparser import HttpType, HttpParser
from pcapparser import parse_pcap
from pcapparser.config import OutputLevel
from pcapparser import utils
import json
import os


# when press Ctrl+C
def signal_handler(signal, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

def handle_tcptrace(c):
    filter = config.get_filter()
    for tcp in get_tcpconn(c.infile):
        if filter.index != None and tcp.index not in filter.index:
            continue

        data = []


        for packet, direct in  tcp.packets:
            flag = '>'
            ddirect = 1
            if direct:
                flag = '<'
                ddirect = 0

            seq = packet.seq - tcp.seq_start[direct]
            if packet.ack:
                ack_seq = packet.ack_seq - tcp.seq_start[ddirect]
            else:
                ack_seq = 0

            win = ack_seq + packet.win
            if tcp.win_scale[0] and tcp.win_scale[1] and not packet.syn:
                win = ack_seq + packet.win << tcp.win_scale[direct]

            second = (packet.second - tcp.time_start)/1000000

            data.append((flag, second, seq, ack_seq, win))


        title = "%s.json" % tcp.index
        print("tcptrace %s:%s --> %s:%s dump to %s" % (tcp.con_tuple[0],
                tcp.con_tuple[1], tcp.con_tuple[2], tcp.con_tuple[3], title))
        info = {}

        open(title, 'w').write(json.dumps(data, indent=4))






def handle_tcp(c):
    filter = config.get_filter()
    for tcp in get_tcpconn(c.infile):
        if filter.index != None and tcp.index not in filter.index:
            continue
        tcp_msg = "\033[31;2m%s [%s:%d] -- -- --> [%s:%d]\033[0m fin: %s\n" % \
                (tcp.index, tcp.con_tuple[0], tcp.con_tuple[1],
                        tcp.con_tuple[2], tcp.con_tuple[3], tcp.fin)
        utils.print(tcp_msg)

def handle_info(c):
    utils.print(parse_pcap.get_infos(c.infile))

def handle_http(c):
    def printheaders(headers):
        l = 0
        for k in headers.keys():
            if l < len(k):
                l = len(k)
        for k, v in headers.items():
            utils.print(k.ljust(l))
            utils.print(': ')
            utils.print(v)
            utils.print('\n')

    filter = config.get_filter()
    level = config.get_config().level

    for tcpcon in get_tcpconn(c.infile):
        if filter.index != None and tcpcon.index not in filter.index:
            continue

        if not (filter.by_con_tuple(tcpcon.con_tuple)):
            continue

        http = HttpParser(tcpcon)

        if not http.msgs:
            continue

        tcp = http.tcp
        tcp_msg = "\033[31;2m%s [%s:%d] -- -- --> [%s:%d]\033[0m\n" % \
                (tcp.index, tcp.con_tuple[0], tcp.con_tuple[1],
                        tcp.con_tuple[2], tcp.con_tuple[3])
        utils.print(tcp_msg)

        if level == OutputLevel.ONLY_URL:
            for msg in http.msgs:
                if msg.is_request:
                    utils.print(msg.reqline["method"] + ' ' + msg.URI())
                    utils.print('\n')
        else:
            for i, msg in enumerate(http.msgs):
                if msg.is_request and i != 0:
                        utils.print('\033[31;2m')
                        utils.print('-' * 80)
                        utils.print('\033[0m')
                        utils.print('\n')

                utils.print(''.join(msg.raw_headers))
                utils.print('\n')
                if level == OutputLevel.ALL_BODY:
                    utils.print(msg.body.getvalue())

def main():
    config.init()
    c = config.get_config()
    maps = {'http': handle_http, 'info': handle_info, 'tcp': handle_tcp,
            'tcptrace': handle_tcptrace}
    handle = maps.get(c.args.target)
    if handle:
        handle(c)

if __name__ == "__main__":
    main()
