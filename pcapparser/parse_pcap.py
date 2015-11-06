from __future__ import unicode_literals, print_function, division
from collections import OrderedDict
import struct
import sys

from pcapparser import packet_parser
from pcapparser import pcap, pcapng, utils
from pcapparser.constant import FileFormat
from pcapparser import config

from pcapparser.utils import is_request
from pcapparser.utils import six

from pcapparser.config import OutputLevel

from tcpconn  import TcpConnection

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

def parse_pcap_file(infile):
    """
    :type infile:file
    """

    conn_dict = OrderedDict()

    file_format, head = get_file_format(infile)
    if file_format == FileFormat.PCAP:
        pcap_file = pcap.PcapFile(infile, head).read_packet
    elif file_format == FileFormat.PCAP_NG:
        pcap_file = pcapng.PcapngFile(infile, head).read_packet
    else:
        print("unknown file format.", file=sys.stderr)
        sys.exit(1)

    _filter = config.get_filter()

    conn_sorted = []
    for tcp_pac in packet_parser.read_tcp_packet(pcap_file):
        # filter
        if not (_filter.by_ip(tcp_pac.source) or _filter.by_ip(tcp_pac.dest)):
            continue
        if not (_filter.by_port(tcp_pac.source_port) or _filter.by_port(tcp_pac.dest_port)):
            continue

        key = tcp_pac.gen_key()
        # we already have this conn
        if key in conn_dict:
            conn_dict[key].on_packet(tcp_pac)
            # conn closed.
            if conn_dict[key].closed():
        #        conn_dict[key].finish()
                del conn_dict[key]

        # begin tcp connection.
        elif tcp_pac.syn and not tcp_pac.ack:
            conn_dict[key] = TcpConnection(tcp_pac)
            conn_sorted.append(conn_dict[key])
        elif utils.is_request(tcp_pac.body):
            # tcp init before capture, we start from a possible http request header.
            conn_dict[key] = TcpConnection(tcp_pac)
            conn_sorted.append(conn_dict[key])

    # finish connection which not close yet
    #for conn in conn_dict.values():
    #    conn.finish()
    for con in conn_sorted:
        con.finish()
    return conn_sorted



