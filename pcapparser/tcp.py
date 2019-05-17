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
    def __init__(self, packet):
        self.inflight = []
        self.fin = False
        self.ack = 0
        self.seqs = []
        self.retransmit = 0
        self.num = 0
        self.dupack = 0

        self.start_time = packet.second
        self.start_seqs = packet.seq
        self.time_spent = -1
        self.bytes_sent = -1
        self.syn_retrains = 0

    def handle_fin(self, packet):
        self.fin = True
        self.bytes_sent = packet.seq - self.start_seqs
        self.time_spent = float(packet.second - self.start_time)/1000/1000


class TcpConn:
    cons = {}
    All = []
    def __init__(self, packet):
        self.rtt = 0
        self.All.append(self)
        self.tuple = packet.tuple
        self.src = packet.skey

        self.win1 = TcpWin(packet)
        self.win2 = None

        self.syn_retrans = 0



    @classmethod
    def handle_packet(cls, packet):
        key = packet.key

        con = cls.cons.get(key)
        if not con:
            if packet.syn and not packet.ack:
                cls.cons[key] = cls(packet)
            return

        if packet.syn:
            con.handle_syn(packet)
            return

        if packet.fin:
            con.handle_fin(packet)
            if con.win1.fin and con.win2.fin:
                del cls.cons[key]
            return


        con.tmp_win1 = None
        con.tmp_win2 = None

        con.handle(packet)
        return con

    def handle_syn(self, packet):
        if packet.skey == self.src:
            self.win1.syn_retrains +=1
            return

        if self.win2:
            self.win2.syn_retrains +=1
            return

        self.win2 = TcpWin(packet)

    def handle_fin(self, packet):
        if packet.skey == self.src:
            self.win1.handle_fin(packet)
        else:
            self.win2.handle_fin(packet)

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
        win1 = con.win1
        win2 = con.win2

        msg = \
"""%s
   retransmit: %s/%s  %.2f%/%.2f%
   dupack:     %s/%s
   psh:        %s/%s
   spent:      %.3f/%.3f
""" % (
                con.tuple,
                win1.retransmit, win2.retransmit,
                float(win1.retransmit)/len(win1.seqs) * 100,
                float(win2.retransmit)/len(win2.seqs) * 100,
                win1.dupack,
                win2.dupack,
                win1.num,
                win2.num,
                win1.time_spent,
                win2.time_spent,
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
    print ">> start draw"

    import matplotlib as mpl
    import matplotlib.dates as mdates
    from matplotlib import rcParams

    rcParams['font.family'] = 'monospace'
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

    plt.suptitle(info, size=30, y=0.98, x=0, ha='left')
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













