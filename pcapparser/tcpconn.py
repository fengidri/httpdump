# -*- coding:utf-8 -*-
#    author    :   丁雪峰
#    time      :   2015-11-06 01:41:51
#    email     :   fengidri@yeah.net
#    version   :   1.0.1
from __future__ import unicode_literals, print_function, division

from pcapparser.packet_parser import TcpPack

class Stream(object):
    def __init__(self):
        self.receive_buf  = []
        self.status       = 0
        self.last_ack_seq = 0

    def append_packet(self, packet):
        """
        :type packet:TcpPack
        """
        if packet.seq >= self.last_ack_seq and packet.body:
            self.receive_buf.append(packet)

    def retrieve_packet(self, ack_seq):
        if ack_seq <= self.last_ack_seq:
            return None

        self.last_ack_seq = ack_seq
        data = []
        new_buf = []
        for packet in self.receive_buf:
            if packet.seq < ack_seq:
                data.append(packet)
            else:
                new_buf.append(packet)
        self.receive_buf = new_buf
        if len(data) <= 1:
            return data
        data.sort(key=lambda pct: pct.seq)
        new_data = []
        last_packet_seq = None
        for packet in data:
            if packet.seq != last_packet_seq:
                last_packet_seq = packet.seq
                new_data.append(packet)
        return new_data


class TcpConnection(object):
    Index = 0
    def __init__(self, packet):
        """
        :type packet: TcpPack
        """
        self.packets = []

        self.win_scale = [0, 0]
        self.seq_start = [0, 0]
        self.time_start = 0


        self.up_stream = Stream()
        self.down_stream = Stream()
        self.client_key = packet.source_key()

        self.index = self.__class__.Index
        self.__class__.Index += 1

        self.on_packet(packet)
        self.con_tuple = (packet.source, packet.source_port,
                packet.dest, packet.dest_port)

        self.msgs = []
        self.fin = ''

    def on_packet(self, packet):
        """
        :type packet: TcpPack
        """

        if packet.source_key() == self.client_key:
            send_stream = self.up_stream
            confirm_stream = self.down_stream
            pac_type = 1
            self.packets.append((packet, 0))
            if packet.syn:
                self.win_scale[0] = packet.win_scal
                self.seq_start[0] = packet.seq
                self.time_start = packet.second
        else:
            self.packets.append((packet, 1))
            send_stream = self.down_stream
            confirm_stream = self.up_stream
            pac_type = 0
            if packet.syn:
                self.win_scale[1] = packet.win_scal
                self.seq_start[1] = packet.seq


        if len(packet.body) > 0:
            send_stream.append_packet(packet)

        if packet.ack:
            packets = confirm_stream.retrieve_packet(packet.ack_seq)
            if packets:
                for packet in packets:
                    self.msgs.append((pac_type, packet.body))

        if packet.fin:
            if not self.fin:
                self.fin = "%s -- > %s"  % (packet.source_port, packet.dest_port)
            send_stream.status = 1

    def closed(self):
        return self.up_stream.status == 1 and self.down_stream.status == 1

if __name__ == "__main__":
    pass


