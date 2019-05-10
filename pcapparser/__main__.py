from __future__ import unicode_literals, print_function, division

import signal
import sys

from pcapparser import config
from pcapparser import parse_pcap
from pcapparser.config import OutputLevel
import pcapparser.parse_pcap as parse_pcap
import handler


# when press Ctrl+C
def signal_handler(signal, frame):
    sys.exit(0)


#signal.signal(signal.SIGINT, signal_handler)


def main():
    c = config.get_config()


    handle = handler.maps.get(c.args.target)
    if handle:
        handle(c)

if __name__ == "__main__":
    main()
