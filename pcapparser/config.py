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




out = None

def init():
    global _parse_config
    global out

    parser = argparse.ArgumentParser()

    #subparsers = parser.add_subparsers(help='sub-command help', dest = 'option')

    #tcp  = subparsers.add_parser('tcp',  help = 'tcp  parser')
    #udp  = subparsers.add_parser('udp',  help = 'udp  parser')
    #http = subparsers.add_parser('http', help = 'http parser')
    #tcp.add_argument("infile", nargs='?', help="the pcap file to parse")


    parser.add_argument("infile", nargs='?', help="the pcap file to parse")
    parser.add_argument("--dport",    default = None, type=int)
    parser.add_argument("--sport",    default = None, type=int)
    parser.add_argument("--port",     default = None, type=int)
    parser.add_argument("--host",     default = None)
    parser.add_argument("--src-host", default = None)
    parser.add_argument("--dst-host", default = None)
    #parser.add_argument("-v", "--verbosity", help="increase output verbosity(-vv is recommended)",
    #                    action="count")
    #parser.add_argument("-g", "--group", help="group http request/response by connection",
    #                    action="store_true")
    parser.add_argument("-o", "--output", help="output to file instead of stdout")
    parser.add_argument("-e", "--encoding", help="decode the data use specified encodings.")
    parser.add_argument("-b", "--beauty", help="output json in a pretty way.", action="store_true")
    parser.add_argument("-d", "--domain", help="filter http data by request domain")
    parser.add_argument("-u", "--uri", help="filter http data by request uri pattern")
    parser.add_argument("-I", "--index", help="select the index")
    parser.add_argument("-t",  dest='target', default = "tcp", help='default: tcp. such as: %s' %
            ','.join([]))
    parser.add_argument("--draw-sport", type=int)
    parser.add_argument("--draw-src-host")
    parser.add_argument("--draw-output")


    args = parser.parse_args()

    file_path = "-" if args.infile is None else args.infile
    if file_path != '-':
        infile = io.open(file_path, "rb")
    else:
        infile = sys.stdin

    _parse_config.infile = infile

    # deal with configs
    parse_config = _parse_config
    #if args.verbosity:
    #    parse_config.level = args.verbosity
    #if args.encoding:
    #    parse_config.encoding = args.encoding
    parse_config.pretty = args.beauty
    #parse_config.group = args.group

    parse_config.args = args

    if args.output:
        output_file = open(args.output, "w+")
    else:
        output_file = sys.stdout

    out = output_file
init()
