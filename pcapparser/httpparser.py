from __future__ import unicode_literals, print_function, division

from collections import defaultdict

from pcapparser import utils
from pcapparser.constant import HttpType, Compress
from pcapparser.reader import DataReader
from pcapparser import config

from pcapparser.config import OutputLevel

from .StreamBuf import Stream


class HttpStream(object):
    def __init__(self):
        self.handle = None
        self.headers = {}
        self.raw_headers = []
        self.body = Stream()
        self._chunked = False
        self._chunked_len = -2# this is special
        self._chunked_stop = False
        self._len = 0

        self.is_request = False

    def read(self, msg):
        while True:
            handle = self.handle
            res = self.handle(msg)
            if handle == self.handle:
                break

        return res

    def headers_handle(self, msg):
        while True:
            line = msg.readline()
            if None == line:
                return

            if '\r\n' == line:
                self.handle = self.body_handle
                break

            self.raw_headers.append(line)

            key, value = utils.parse_http_header(line)
            self.headers[key] = value
            if key == None:
                continue

            if key == 'content-length':
                self._len = int(value)

            elif key == 'transfer-encoding':
                if value.find("chunked") > -1:
                    self._chunked = True

    def body_handle(self, msg):
        if self._chunked:
            return self.read_chunked_body(msg)

        if self._len != -1:
            t = msg.read(self._len)
            self.body.write(t)
            self._len -= len(t)

        if 0 == self._len:
            return 0 # OVER


    def read_chunked_body(self, msg):
        """ read chunked body """
        if self._chunked_len > 0:
            t = msg.read(self._chunked_len)
            self.body.write(t)
            self._chunked_len -= len(t)

        if self._chunked_len <= 0 and self._chunked_len > -2:
            t = msg.read(2 + self._chunked_len)
            self._chunked_len -= len(t)

        if self._chunked_len == -2:
            if self._chunked_stop:
                return 0

            line = msg.readline()
            chunk_size_end = line.find(b';')
            if chunk_size_end < 0:
                chunk_size_end = len(line)
                # skip chunk extension
            chunk_size_str = line[0:chunk_size_end]
            if chunk_size_str[0] == b'0':
                self._chunked_stop = True
                self._chunked_len = 0
                return self.read_chunked_body(msg)

            try:
                chunk_len = int(chunk_size_str, 16)
                self._chunked_len = chunk_len
                return self.read_chunked_body(msg)
            except:
                pass



class HttpRequest(HttpStream):
    def __init__(self):
        HttpStream.__init__(self)
        self.reqline = {}

        self.handle = self.reqline_handle
        self.is_request = True


    def reqline_handle(self, msg):
        line = msg.readline()
        if not line:
            return

        items = line.split(' ')
        if len(items) < 2:
            return -1 # NOT HTTP

        self.raw_headers.append(line)
        self.reqline['method'] = items[0]
        self.reqline['uri'] = items[1]
        self.handle = self.headers_handle

        # handle the headrs over


    def URI(self):
        uri = self.reqline["uri"]
        if uri.startswith(b'http://') or uri.startswith(b'https://'):
            return self.uri
        else:
            host = self.headers.get("host")
            if host:
                return b'http://' + host + uri
            else:
                return uri


class HttpResponse(HttpStream):
    def __init__(self):
        HttpStream.__init__(self)
        self.resline = {}

        self.handle = self.resline_handle

    def resline_handle(self, msg):
        line = msg.readline()
        if not line:
            return

        items = line.split(' ')
        if len(items) < 2:
            return -1 # NOT HTTP

        self.raw_headers.append(line)
        self.resline['status'] = items[1]
        self.handle = self.headers_handle



class HttpParser(object):
    ERRNO_NUM     = 0
    ERRNO_NOTHTTP = 1
    """parse http req & resp"""
    def __init__(self, tcp):
        """
        :type processor: HttpDataProcessor
        """
        self.tcp = tcp
        self.errno = 0

        self.stream =  [Stream(), Stream()]
        self.handles = [None, None]

        self.msgs = []

        for msg in tcp.msgs:
            err = self.read_msg(*msg)
            if err:
                break

    def read_msg(self, http_type, data):
        stream = self.stream[http_type]

        pos = stream.tell()
        stream.seek(0, 2)
        stream.write(data)
        stream.seek(pos)

        while True:
            rr = self.handles[http_type]
            if None == rr:
                pos = stream.tell()
                line = stream.readline() # TODO maybe too big
                if not line:
                    return

                if line[-10:-5].lower() == 'http/': # the line ends with \r\n
                    rr = HttpRequest()
                elif line[0:5].lower() == 'http/':
                    rr = HttpResponse()
                else:
                    return self.ERRNO_NOTHTTP

                self.msgs.append(rr)
                self.handles[http_type] = rr
                stream.seek(pos)

            res = rr.read(stream)
            if 0 != res:
                return res

            self.handles[http_type] = None

    def print(self, level):
        if not self.msgs:
            return

        tcp = self.tcp
        tcp_msg = "\033[31;2m%s [%s:%d] -- -- --> [%s:%d]\033[0m" % \
                (tcp.index, tcp.con_tuple[0], tcp.con_tuple[1],
                        tcp.con_tuple[2], tcp.con_tuple[3])
        utils.print(tcp_msg)
        utils.print('\n')

        if level == OutputLevel.ONLY_URL:
            for msg in self.msgs:
                if msg.is_request:
                    utils.print(msg.reqline["method"] + ' ' + msg.URI())
                    utils.print('\n')
        else:
            for i, msg in enumerate(self.msgs):
                if msg.is_request:
                    if i != 0:
                        utils.print('-' * 80)
                        utils.print('\n')

                    for line in msg.raw_headers:
                        utils.print(line)
                    utils.print('\n')
                    utils.print('\n')
                else:
                    for line in msg.raw_headers:
                        utils.print(line)
                    utils.print('\n')
                    utils.print('\n')

