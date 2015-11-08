from __future__ import unicode_literals, print_function, division
import sys
import argparse
import io

__author__ = 'dongliu'


class OutputLevel(object):
    ONLY_URL = 0
    HEADER = 1
    TEXT_BODY = 2
    ALL_BODY = 3


class ParseConfig(object):
    """ global settings """

    def __init__(self):
        self.level = OutputLevel.ONLY_URL
        self.pretty = False
        self.encoding = None
        self.group = False
        self.infile = None


_parse_config = ParseConfig()


def get_config():
    global _parse_config
    return _parse_config


class Filter(object):
    """filter settings"""

    def __init__(self):
        self.ip = None
        self.port = None
        self.domain = None
        self.uri_pattern = None
        self.index = None

    def by_ip(self, ip):
        return not self.ip or self.ip == ip

    def by_port(self, port):
        return not self.port or self.port == port

    def by_domain(self, domain):
        return not self.domain or self.domain == domain

    def by_uri(self, uri):
        return not self.uri_pattern or self.uri_pattern in uri

    def by_con_tuple(self, con_tuple):
        return True
        pass #TODO

    #def by_index(self, index):


_filter = Filter()
out = None


def get_filter():
    global _filter
    return _filter

def init():
    global _filter
    global _parse_config
    global out
    parser = argparse.ArgumentParser()
    parser.add_argument("infile", nargs='?', help="the pcap file to parse")
    parser.add_argument("-i", "--ip", help="only parse packages with specified source OR dest ip")
    parser.add_argument("-p", "--port", type=int,
                        help="only parse packages with specified source OR dest port")
    parser.add_argument("-v", "--verbosity", help="increase output verbosity(-vv is recommended)",
                        action="count")
    parser.add_argument("-g", "--group", help="group http request/response by connection",
                        action="store_true")
    parser.add_argument("-o", "--output", help="output to file instead of stdout")
    parser.add_argument("-e", "--encoding", help="decode the data use specified encodings.")
    parser.add_argument("-b", "--beauty", help="output json in a pretty way.", action="store_true")
    parser.add_argument("-d", "--domain", help="filter http data by request domain")
    parser.add_argument("-u", "--uri", help="filter http data by request uri pattern")
    parser.add_argument("-I", "--index", help="select the index")
    parser.add_argument("-t", "--target", default = "http")

    args = parser.parse_args()

    file_path = "-" if args.infile is None else args.infile
    if file_path != '-':
        infile = io.open(file_path, "rb")
    else:
        infile = sys.stdin

    _parse_config.infile = infile

    _filter.ip = args.ip
    _filter.port = args.port
    _filter.domain = args.domain
    _filter.uri_pattern = args.uri
    if args.index:
        _filter.index = []
        for i in args.index.split(','):
            if i.find('-') > -1:
                s, e = i.split('-')
                _filter.index += range(int(s), int(e) + 1)
            else:
                _filter.index.append(int(i))
    else:
        _filter.index = None

    # deal with configs
    parse_config = _parse_config
    if args.verbosity:
        parse_config.level = args.verbosity
    if args.encoding:
        parse_config.encoding = args.encoding
    parse_config.pretty = args.beauty
    parse_config.group = args.group

    parse_config.args = args

    if args.output:
        output_file = open(args.output, "w+")
    else:
        output_file = sys.stdout

    out = output_file

