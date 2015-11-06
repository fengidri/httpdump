from __future__ import unicode_literals, print_function, division

import signal
import sys

from pcapparser.parse_pcap import parse_pcap_file
from pcapparser import config


# when press Ctrl+C
def signal_handler(signal, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def main():
    config.init()

    for tcpcon in parse_pcap_file(config.get_config().infile):
        tcpcon.http_parser.print(config.get_config().level)


if __name__ == "__main__":
    main()
