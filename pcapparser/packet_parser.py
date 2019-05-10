from __future__ import unicode_literals, print_function, division

__author__ = 'dongliu'

import struct
import socket
from pcapparser.constant import *
from pcapparser import pcap, pcapng, utils
import config

class filter:
    dst_port = config.get_config().args.dport
    src_port = config.get_config().args.sport
    port     = config.get_config().args.port
    host     = config.get_config().args.host
    dst_host = config.get_config().args.dst_host
    src_host = config.get_config().args.src_host

    draw_sport = config.get_config().args.draw_sport
    draw_src_host = config.get_config().args.draw_src_host


class TcpPack:
    """ a tcp packet, header fields and data. """
    def __init__(self, sec, source, dest, ipbody):
        self.second = sec
        self.source = source
        self.dest = dest
        self.key = None
        self.parse_tcp_packet(ipbody)

        skey = '%s:%d' % (self.source, self.source_port)
        dkey = '%s:%d' % (self.dest, self.dest_port)
        if skey < dkey:
            self.direct = 1
            self.key = skey + '-' + dkey
        else:
            self.direct = 0
            self.key = dkey + '-' + skey

        self.tuple = "%s -> %s" %(skey, dkey)
        self.skey = skey
        self.dkey = dkey

    def parse_tcp_packet(self, tcp_packet):
        """read tcp data.http only build on tcp, so we do not need to support other protocols."""
        tcp_base_header_len = 20
        # tcp header
        tcp_header = tcp_packet[0:tcp_base_header_len]
        source_port, dest_port, seq, ack_seq, t_f, flags = struct.unpack(b'!HHIIBB6x', tcp_header)
        # real tcp header len
        tcp_header_len = ((t_f >> 4) & 0xF) * 4
        # skip extension headers
        if tcp_header_len > tcp_base_header_len:
            pass

        # body
        self.body = tcp_packet[tcp_header_len:]

        self.source_port = source_port
        self.dest_port = dest_port
        self.flags = flags
        self.seq = seq
        self.ack_seq = ack_seq
        self.fin = flags & 1
        self.syn = (flags >> 1) & 1
        # rst = (flags >> 2) & 1
        # psh = (flags >> 3) & 1
        self.ack = (flags >> 4) & 1
        # urg = (flags >> 5) & 1


    def __str__(self):
        return "%s:%d  -->  %s:%d, seq:%d, ack_seq:%s size:%d fin:%d syn:%d ack:%d" % \
               (self.source, self.source_port, self.dest, self.dest_port, self.seq,
                self.ack_seq, len(self.body), self.fin, self.syn, self.ack)

    def gen_key(self):
        return self.key

    def source_key(self):
        return '%s:%d' % (self.source, self.source_port)

    def draw_check(self):
        if filter.draw_sport:
            if filter.draw_sport != self.source_port:
                return False

        if filter.draw_src_host:
            if filter.args.draw_src_host != self.source:
                return False

        return True


# http://standards.ieee.org/about/get/802/802.3.html
def dl_parse_ethernet(link_packet):
    """ parse Ethernet packet """

    eth_header_len = 14
    # ethernet header
    ethernet_header = link_packet[0:eth_header_len]

    (network_protocol, ) = struct.unpack(b'!12xH', ethernet_header)
    if network_protocol == NetworkProtocol.P802_1Q:
        # 802.1q, we need to skip two bytes and read another two bytes to get protocol/len
        type_or_len = link_packet[eth_header_len:eth_header_len + 4]
        eth_header_len += 4
        network_protocol, = struct.unpack(b'!2xH', type_or_len)
    if network_protocol == NetworkProtocol.PPPOE_SESSION:
        # skip PPPOE SESSION Header
        eth_header_len += 8
        type_or_len = link_packet[eth_header_len - 2:eth_header_len]
        network_protocol, = struct.unpack(b'!H', type_or_len)
    if network_protocol < 1536:
        # TODO n_protocol means package len
        pass
    return network_protocol, link_packet[eth_header_len:]


# http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
def dl_parse_linux_sll(link_packet):
    """ parse linux sll packet """

    sll_header_len = 16

    # Linux cooked header
    linux_cooked = link_packet[0:sll_header_len]

    packet_type, link_type_address_type, link_type_address_len, link_type_address, n_protocol \
        = struct.unpack(b'!HHHQH', linux_cooked)
    return n_protocol, link_packet[sll_header_len:]


# see http://en.wikipedia.org/wiki/Ethertype
def parse_ip_packet(network_protocol, ip_packet):
    # ip header
    if network_protocol == NetworkProtocol.IP or network_protocol == NetworkProtocol.PPP_IP:
        ip_base_header_len = 20
        ip_header = ip_packet[0:ip_base_header_len]
        (ip_info, ip_length, transport_protocol) = struct.unpack(b'!BxH5xB10x', ip_header)
        # real ip header len.
        ip_header_len = (ip_info & 0xF) * 4
        ip_version = (ip_info >> 4) & 0xF

        # skip all extra header fields.
        if ip_header_len > ip_base_header_len:
            pass

        source = socket.inet_ntoa(ip_header[12:16])
        dest = socket.inet_ntoa(ip_header[16:])

        return transport_protocol, source, dest, ip_packet[ip_header_len:ip_length]
    elif network_protocol == NetworkProtocol.IPV6:
        # TODO: deal with ipv6 package
        return None, None, None, None
    else:
        # skip
        return None, None, None, None




def get_link_layer_parser(link_type):
    if link_type == LinkLayerType.ETHERNET:
        return dl_parse_ethernet
    elif link_type == LinkLayerType.LINUX_SLL:
        return dl_parse_linux_sll
    else:
        return None


def parse_udp_packet(ip_body):
    udp_header = ip_body[0:8]
    source_port, dest_port, length, check_sum = struct.unpack(b'!HHHH', udp_header)
    return source_port, dest_port, ip_body[8:length]

def get_file_format(infile):
    """
    get cap file format by magic num.
    return file format and the first byte of string
    :type infile:file
    """
    buf = infile.read(4)
    if len(buf) == 0:
        # EOF
        print("empty file", file=sys.stderr)
        sys.exit(-1)
    if len(buf) < 4:
        print("file too small", file=sys.stderr)
        sys.exit(-1)
    magic_num, = struct.unpack(b'<I', buf)
    if magic_num == 0xA1B2C3D4 or magic_num == 0x4D3C2B1A:
        return FileFormat.PCAP, buf
    elif magic_num == 0x0A0D0D0A:
        return FileFormat.PCAP_NG, buf
    else:
        return FileFormat.UNKNOWN, buf

class PcapFile(object):
    def __init__(self, infile):
        self.infile = infile

        file_format, head = get_file_format(infile)
        if file_format == FileFormat.PCAP:
            pcap_file = pcap.PcapFile(infile, head)
        elif file_format == FileFormat.PCAP_NG:
            pcap_file = pcapng.PcapngFile(infile, head)
        else:
            print("unknown file format.", file=sys.stderr)
            sys.exit(1)

        self.pcap_file = pcap_file

    def __iter__(self):
        self.iter = self.pcap_file.read_packet()
        return self

    def next(self):
        while True:
            link_type, micro_second, link_packet = self.iter.next()

            parse_link_layer = get_link_layer_parser(link_type)
            if parse_link_layer is None:
                # skip unknown link layer packet
                continue

            network_protocol, link_layer_body = parse_link_layer(link_packet)

            transport_protocol, source, dest, ip_body = \
                        parse_ip_packet(network_protocol, link_layer_body)

            if transport_protocol is None:
                continue

            if filter.dst_host:
                if filter.dst_host != dst:
                    continue

            if filter.src_host:
                if ilter.src_host != source:
                    continue

            if filter.host:
                if not (filter.host == dst or filter.host == source):
                    continue

            # tcp
            if transport_protocol == TransferProtocol.TCP:
                t = TcpPack(micro_second, source, dest, ip_body)
                if filter.dst_port:
                    if filter.dst_port != t.dest_port:
                        continue

                if filter.src_port:
                    if ilter.src_port != t.source_port:
                        continue

                if filter.port:
                    if not (filter.port == t.dest_port or
                            filter.port == t.source_port):
                        continue
                return t



def info(read_packet):
    packet_total = 0
    packet_tcp   = 0
    packet_udp   = 0
    packet_arp   = 0
    packet_icmp  = 0

    for link_type, micro_second, link_packet in read_packet():
        packet_total += 1

        parse_link_layer = get_link_layer_parser(link_type)
        if parse_link_layer is None:
            # skip unknown link layer packet
            continue

        network_protocol, link_layer_body = parse_link_layer(link_packet)
        transport_protocol, source, dest, ip_body = parse_ip_packet(network_protocol, link_layer_body)

        if transport_protocol is None:
            continue

        # tcp
        if transport_protocol == TransferProtocol.TCP:
            packet_tcp += 1
        elif transport_protocol == TransferProtocol.UDP:
            packet_udp += 1
        elif transport_protocol == TransferProtocol.UDP:
            packet_udp += 1
        elif transport_protocol == TransferProtocol.ICMP:
            packet_icmp += 1
        elif transport_protocol == TransferProtocol.ICMP:
            packet_icmp += 1
    msg = """Packet:
Total: %s
TCP  : %s
UDP  : %s
ICMP : %s
"""
    return  msg % (packet_total, packet_tcp, packet_udp, packet_icmp)




















