from __future__ import unicode_literals, print_function, division

import signal
import sys

from pcapparser.parse_pcap import parse_pcap_file
from pcapparser import config
from pcapparser.httpparser import HttpType, HttpParser


# when press Ctrl+C
def signal_handler(signal, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def main():
    config.init()

    filter = config.get_filter()
    for tcpcon in parse_pcap_file(config.get_config().infile):
        if filter.index != None and tcpcon.index not in filter.index:
            continue

        if not (filter.by_con_tuple(tcpcon.con_tuple)):
            continue

        http = HttpParser(tcpcon)
        http.print(config.get_config().level)


if __name__ == "__main__":
    main()
