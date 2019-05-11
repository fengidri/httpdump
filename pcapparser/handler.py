# -*- coding:utf-8 -*-
#    author    :   丁雪峰
#    time      :   2019-05-10 17:25:48
#    email     :   fengidri@yeah.net
#    version   :   1.0.1


import tcp
import utils
from pcapparser.httpparser import HttpType, HttpParser
import parse_pcap


def handle_tcp(c):
    for con in tcp.get_tcpconn(c):
        msg = "%s retransmit: %s/%s dupack: %s/%s psh: %s/%s\n" % (
                con.tuple,
                con.win1.retransmit,
                con.win2.retransmit,
                con.win1.dupack,
                con.win2.dupack,
                con.win1.num,
                con.win2.num,
                )

        utils.log(msg)

def handle_info(c):
    utils.log(parse_pcap.get_infos(c.infile))

def handle_http(c):
    def printheaders(headers):
        l = 0
        for k in headers.keys():
            if l < len(k):
                l = len(k)
        for k, v in headers.items():
            utils.log(k.ljust(l))
            utils.log(': ')
            utils.log(v)
            utils.log('\n')

    import config
    level = config.get_config().level

    for tcpcon in tcp.get_tcpconn(c.infile):

        http = HttpParser(tcpcon)

        if not http.msgs:
            continue

        tcp = http.tcp
        tcp_msg = "\033[31;2m%s [%s:%d] -- -- --> [%s:%d]\033[0m\n" % \
                (tcp.index, tcp.con_tuple[0], tcp.con_tuple[1],
                        tcp.con_tuple[2], tcp.con_tuple[3])
        utils.log(tcp_msg)

        if level == OutputLevel.ONLY_URL:
            for msg in http.msgs:
                if msg.is_request:
                    utils.log(msg.reqline["method"] + ' ' + msg.URI())
                    utils.log('\n')
        else:
            for i, msg in enumerate(http.msgs):
                if msg.is_request and i != 0:
                        utils.log('\033[31;2m')
                        utils.log('-' * 80)
                        utils.log('\033[0m')
                        utils.log('\n')

                utils.log(''.join(msg.raw_headers))
                utils.log('\n')
                if level == OutputLevel.ALL_BODY:
                    utils.log(msg.body.getvalue())


maps = {
        'http': handle_http,
        'info': handle_info,
        'tcp': handle_tcp,
        'tcp-flight': tcp.get_tcpconn_flight,
        'tcp-throughput': tcp.get_tcpconn_throughput,
        'tcp-seq': tcp.get_tcpconn_seq,
        'tcp-rtt': tcp.get_tcpconn_rtt,
        }
