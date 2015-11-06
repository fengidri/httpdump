# -*- coding:utf-8 -*-
#    author    :   丁雪峰
#    time      :   2015-11-06 01:41:51
#    email     :   fengidri@yeah.net
#    version   :   1.0.1
from __future__ import unicode_literals, print_function, division
from collections import OrderedDict
import struct
import sys

from pcapparser.packet_parser import TcpPack
from pcapparser.printer import HttpPrinter
from pcapparser.httpparser import HttpType, HttpParser
from pcapparser.utils import is_request

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
        self.up_stream = Stream()
        self.down_stream = Stream()
        self.client_key = packet.source_key()

        self.index = self.__class__.Index
        self.__class__.Index += 1

        self.is_http = None
        self.http_parser = HttpParser(self)
        self.on_packet(packet)
        self.con_tuple = (packet.source, packet.source_port,
                packet.dest, packet.dest_port)

    def on_packet(self, packet):
        """
        :type packet: TcpPack
        """
        if self.is_http is None and packet.body:
            self.is_http = is_request(packet.body)

        if self.is_http == False:
            return

        if packet.source_key() == self.client_key:
            send_stream = self.up_stream
            confirm_stream = self.down_stream
            pac_type = HttpType.RESPONSE
        else:
            send_stream = self.down_stream
            confirm_stream = self.up_stream
            pac_type = HttpType.REQUEST

        if len(packet.body) > 0:
            send_stream.append_packet(packet)
        if packet.syn:
            pass
        if packet.ack:
            packets = confirm_stream.retrieve_packet(packet.ack_seq)
            if packets:
                for packet in packets:
                    self.http_parser.send(pac_type, packet.body)
        if packet.fin:
            send_stream.status = 1

    def closed(self):
        return self.up_stream.status == 1 and self.down_stream.status == 1

    def finish(self):
        self.http_parser.finish()
        #value = self.processor.buf.getvalue()
        #if not value:
        #    return

        #try:
        #    config.out.write(

        #    if config.get_config().level != OutputLevel.ONLY_URL:
        #        config.out.write('\n')
        #    else:
        #        config.out.write('\t')


        #    config.out.write(value)

        #    config.out.flush()

if __name__ == "__main__":
    pass


