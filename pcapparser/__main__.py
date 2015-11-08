from __future__ import unicode_literals, print_function, division

import signal
import sys

from pcapparser.parse_pcap import get_tcpconn
from pcapparser import config
from pcapparser.httpparser import HttpType, HttpParser
from pcapparser import parse_pcap
import utils


# when press Ctrl+C
def signal_handler(signal, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

def main():
    config.init()
    c = config.get_config()
    maps = {'http': handle_http, 'info': handle_info}
    handle = maps.get(c.args.target)
    if handle:
        handle(c)

def handle_info(c):
    utils.print(parse_pcap.get_infos(c.infile))

def handle_http(c):
    filter = config.get_filter()
    for tcpcon in get_tcpconn(c.infile):
        if filter.index != None and tcpcon.index not in filter.index:
            continue

        if not (filter.by_con_tuple(tcpcon.con_tuple)):
            continue

        http = HttpParser(tcpcon)
        http.print(config.get_config().level)


if __name__ == "__main__":
    main()
