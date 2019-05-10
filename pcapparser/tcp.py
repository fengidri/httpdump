# -*- coding:utf-8 -*-
#    author    :   丁雪峰
#    time      :   2019-05-10 16:05:58
#    email     :   fengidri@yeah.net
#    version   :   1.0.1


import parse_pcap
from pcapparser import packet_parser

class TcpWin:
    def __init__(self):
        self.inflight = []
        self.fin = False
        self.ack = 0


class TcpConn:
    cons = {}
    def __init__(self):
        self.win1 = TcpWin()
        self.win2 = TcpWin()


    @classmethod
    def handle_packet(cls, packet):
        key = packet.key
        if packet.syn and not packet.ack:
            cls.cons[key] = cls()
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
        if packet.direct:
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
            for s in win2.inflight:
                if s < win2.ack:
                    win2.inflight.remove(s)

        if packet.seq >= win1.ack:
            win1.inflight.append(packet.seq)

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





def get_tcpconn_flight(c):
    pcap_file = parse_pcap.parse_pcap_file(c.infile)

    data = []

    for tcp_pac in packet_parser.read_tcp_packet(pcap_file):
        con = TcpConn.handle_packet(tcp_pac)

        if c.args.draw_source == tcp_pac.skey and con and con.tmp_win1:
             win1 = con.tmp_win1
             data.append([tcp_pac.second, len(win1.inflight)])

    x, y = zip(*data)
    draw_flight(x, y, 'inflight', 'Time', 'packet', c.args.draw_output)


def get_tcpconn_throughput(c):
    pcap_file = parse_pcap.parse_pcap_file(c.infile)

    data = {}

    inter = 10 * 1000

    for tcp_pac in packet_parser.read_tcp_packet(pcap_file):
        if c.args.draw_source == tcp_pac.skey:
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
    pcap_file = parse_pcap.parse_pcap_file(c.infile)

    data = []

    for tcp_pac in packet_parser.read_tcp_packet(pcap_file):
        if c.args.draw_source == tcp_pac.skey:
             data.append([tcp_pac.second, tcp_pac.seq])

    x, y = zip(*data)
    draw_flight(x, y, 'seq', 'Time', 'seq', c.args.draw_output)












