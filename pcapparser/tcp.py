# -*- coding:utf-8 -*-
#    author    :   丁雪峰
#    time      :   2019-05-10 16:05:58
#    email     :   fengidri@yeah.net
#    version   :   1.0.1


import parse_pcap
from pcapparser import packet_parser
from collections import OrderedDict
from packet_parser import PcapFile
import utils

class TcpWin:
    def __init__(self):
        self.inflight = []
        self.fin = False
        self.ack = 0
        self.seqs = []
        self.retransmit = 0
        self.num = 0
        self.dupack = 0


class TcpConn:
    cons = {}
    All = []
    def __init__(self, packet):
        self.win1 = TcpWin()
        self.win2 = TcpWin()
        self.rtt = 0
        self.All.append(self)
        self.tuple = packet.tuple
        self.src = packet.skey


    @classmethod
    def handle_packet(cls, packet):
        key = packet.key
        if packet.syn and not packet.ack:
            cls.cons[key] = cls(packet)
            return

        if packet.fin and cls.cons.get(key):
            del cls.cons[key]
            return

        con = cls.cons.get(key)
        if not con:
            # TODO
            return

        con.tmp_win1 = None
        con.tmp_win2 = None

        con.handle(packet)
        return con

    def handle(self, packet):
        if packet.skey == self.src:
            win1 = self.win1
            win2 = self.win2
        else:
            win1 = self.win2
            win2 = self.win1

        if packet.syn:
            return

        if packet.fin:
            win1.fin = True
            return


        if packet.ack_seq > win2.ack:
            win2.ack = packet.ack_seq
            for p in win2.inflight:
                if p.seq < win2.ack:
                    self.rtt = (packet.second - p.second)/1000
                    win2.inflight.remove(p)

        if packet.body:
            win1.num += 1
            if packet.seq in win1.seqs:
                win1.retransmit += 1
            else:
                win1.seqs.append(packet.seq)
                win1.inflight.append(packet)
        else:
            if packet.ack_seq == win2.ack:
                win1.dupack += 1

        self.tmp_win1 = win1
        self.tmp_win2 = win2

    def info(self):
        con = self

        msg = "%s retransmit: %s/%s dupack: %s/%s psh: %s/%s" % (
                con.tuple,
                con.win1.retransmit,
                con.win2.retransmit,
                con.win1.dupack,
                con.win2.dupack,
                con.win1.num,
                con.win2.num,
                )
        return msg



def draw_sub(plt, d):
    opt_x      = d[0]
    opt_y      = d[1]

    plt.plot(opt_x, opt_y) #拆线图
#    plt.scatter(opt_x, opt_y) # 点图

    #plt.xlabel(d[3])
    plt.ylabel(d[4])
    plt.title(d[2])

#    ax = plt.gca()


def draw_flight(info, draws, output):
    import matplotlib as mpl
    import matplotlib.dates as mdates
    mpl.use("Agg")

    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator, FuncFormatter

    plt.figure(figsize=(20, 10.5 * len(draws)))

    size = len(draws) * 100 + 11

    plt.subplots_adjust(
            top=0.92, bottom=0.08, left=0.10, right=0.95, hspace=0.25,
                    wspace=0.35)

#    size += 1
#    plt.subplot(size)
#    plt.text(0.5, 0.5, info, ha='center', va='center', size=20)

    for i, d in enumerate(draws):
        plt.subplot(size + i)
        draw_sub(plt, d)

    plt.xlabel(d[3])

#    ax.xaxis.set_major_locator(MultipleLocator(300 * 12))
#    ax.xaxis.set_major_formatter(FuncFormatter(time_formatter))
#    ax.xaxis.set_minor_locator( MultipleLocator(300) )
#    ax.xaxis.set_major_locator(mdates.MinuteLocator(byminute=[0,30], interval=30))

    plt.suptitle(info, size=30, y=0.95)
    plt.savefig(output)


def get_tcpconn(c):
    for tcp_pac in PcapFile(c.infile):
        TcpConn.handle_packet(tcp_pac)

    return TcpConn.All

#    conn_dict = OrderedDict()
#    conn_sorted = []
#    for tcp_pac in PcapFile(infile):
#        key = tcp_pac.gen_key()
#        # we already have this conn
#        if key in conn_dict:
#            conn_dict[key].on_packet(tcp_pac)
#            # conn closed.
#            if conn_dict[key].closed():
#                del conn_dict[key]
#
#        # begin tcp connection.
#        elif tcp_pac.syn and not tcp_pac.ack:
#            conn_dict[key] = TcpConnection(tcp_pac)
#            conn_sorted.append(conn_dict[key])
#
#        elif utils.is_request(tcp_pac.body):
#            # tcp init before capture, we start from a possible http request header.
#            conn_dict[key] = TcpConnection(tcp_pac)
#            conn_sorted.append(conn_dict[key])
#
#    return conn_sorted


def tcp_status(c):
    flight = []
    throughtput = {}
    seqs = []
    rtt = []
    cons = []

    inter = 100 * 1000

    for tcp_pac in PcapFile(c.infile):
        con = TcpConn.handle_packet(tcp_pac)

        if not tcp_pac.draw_check():
            continue

        if con and con not in cons:
            cons.append(con)


        # seq
        seqs.append([tcp_pac.second, tcp_pac.seq])

        #throughtput
        s = int(tcp_pac.second / inter) * inter
        if throughtput.get(s):
            throughtput[s] = throughtput[s] + 1
        else:
            throughtput[s] = 1

        #rtt
        if con:
            rtt.append([tcp_pac.second, con.rtt])

            if con.tmp_win1:
                 #inflight
                 win1 = con.tmp_win1
                 flight.append([tcp_pac.second, len(win1.inflight)])

    draws = []


    if c.args.target in ['tcp-seqs', 'tcp-all']:
        x, y = zip(*seqs)
        seqs = (x, y, 'seq', 'Time', 'seq')
        draws.append(seqs)

    if c.args.target in ['tcp-throughtput', 'tcp-all']:
        x = throughtput.keys()
        x.sort()
        y = [throughtput[_] for _ in x]

        thoughtput = (x, y, 'throughput', 'Time', 'packet')
        draws.append(thoughtput)

    if c.args.target in ['tcp-flight', 'tcp-all']:
        x, y = zip(*flight)
        flight = (x, y, 'inflight', 'Time', 'packet')
        draws.append(flight)

    if c.args.target in ['tcp-rtt', 'tcp-all']:
        x, y = zip(*rtt)
        rtt = (x, y, 'rtt', 'Time', 'ms')
        draws.append(rtt)

    info = '\n'.join([con.info() for con in cons])
    draw_flight(info, draws, c.args.draw_output)













