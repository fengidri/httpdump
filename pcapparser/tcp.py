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



def draw_flight(x, y, opt_title, opt_xlabel, opt_ylabel, output):
#    x, y = zip(*data)

    #####################################################
    opt_x      = x
    opt_y      = y
#    opt_title  = "inflight"
#    opt_xlabel = "Time"
#    opt_ylabel = "flight"
    #####################################################

    import matplotlib as mpl
    import matplotlib.dates as mdates
    mpl.use("Agg")

    import matplotlib.pyplot as plt
    from matplotlib.ticker import MultipleLocator, FuncFormatter

    plt.figure(figsize=(20, 10.5))
    plt.plot(opt_x, opt_y) #拆线图
#    plt.scatter(opt_x, opt_y) # 点图
    plt.xlabel(opt_xlabel)
    plt.ylabel(opt_ylabel)
    plt.title(opt_title)
    #plt.ylim()
    #plt.legend()

    ax = plt.gca()
#    ax.xaxis.set_major_locator(MultipleLocator(300 * 12))
#    ax.xaxis.set_major_formatter(FuncFormatter(time_formatter))
#    ax.xaxis.set_minor_locator( MultipleLocator(300) )
#    ax.xaxis.set_major_locator(mdates.MinuteLocator(byminute=[0,30], interval=30))

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



def get_tcpconn_flight(c):
    data = []

    for tcp_pac in PcapFile(c.infile):
        con = TcpConn.handle_packet(tcp_pac)

        if tcp_pac.draw_check() and con and con.tmp_win1:
             win1 = con.tmp_win1
             data.append([tcp_pac.second, len(win1.inflight)])

    x, y = zip(*data)
    draw_flight(x, y, 'inflight', 'Time', 'packet', c.args.draw_output)


def get_tcpconn_throughput(c):
    data = {}

    inter = 10 * 1000

    for tcp_pac in PcapFile(c.infile):
        if tcp_pac.draw_check():
            s = int(tcp_pac.second / inter) * inter
            if data.get(s):
                data[s] = data[s] + 1
            else:
                data[s] = 1


    x = data.keys()
    x.sort()
    y = [data[_] for _ in x]

    draw_flight(x, y, 'throughput', 'Time', 'packet', c.args.draw_output)






def get_tcpconn_seq(c):
    data = []

    for tcp_pac in PcapFile(c.infile):
        if tcp_pac.draw_check():
             data.append([tcp_pac.second, tcp_pac.seq])

    x, y = zip(*data)
    draw_flight(x, y, 'seq', 'Time', 'seq', c.args.draw_output)



def get_tcpconn_rtt(c):
    data = []

    for tcp_pac in PcapFile(c.infile):
        con = TcpConn.handle_packet(tcp_pac)

        if con and tcp_pac.draw_check():
             data.append([tcp_pac.second, con.rtt])

    x, y = zip(*data)
    draw_flight(x, y, 'rtt', 'Time', 'ms', c.args.draw_output)









