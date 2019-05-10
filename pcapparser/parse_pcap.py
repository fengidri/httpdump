from __future__ import unicode_literals, print_function, division
import struct
import sys

from pcapparser import packet_parser
from pcapparser import pcap, pcapng, utils
from pcapparser.constant import FileFormat

from pcapparser.utils import is_request



def parse_pcap_file(infile):
    """
    :type infile:file
    """




def get_infos(infile):
    pcap_file = parse_pcap_file(infile)
    return packet_parser.info(pcap_file)


