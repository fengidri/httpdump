from __future__ import unicode_literals, print_function, division

from collections import defaultdict

from pcapparser import utils
from pcapparser.constant import HttpType, Compress
from pcapparser.reader import DataReader
from pcapparser import config

from pcapparser.config import OutputLevel
from StringIO import StringIO

class Stream(StringIO):
    def readline(self, length=None):
        r"""Read one entire line from the file.

        A trailing newline character is kept in the string (but may be absent
        when a file ends with an incomplete line). If the size argument is
        present and non-negative, it is a maximum byte count (including the
        trailing newline) and an incomplete line may be returned.

        An empty string is returned only when EOF is encountered immediately.

        Note: Unlike stdio's fgets(), the returned string contains null
        characters ('\0') if they occurred in the input.
        """
        _complain_ifclosed(self.closed)
        if self.buflist:
            self.buf += ''.join(self.buflist)
            self.buflist = []
        i = self.buf.find('\n', self.pos)
        if i < 0:
            return None # rewrite the code of StringIO
        else:
            newpos = i+1
        if length is not None and length >= 0:
            if self.pos + length < newpos:
                newpos = self.pos + length
        r = self.buf[self.pos:newpos]
        self.pos = newpos
        return r


class HttpStream(object):
    def __init__(self):
        self.handle = None
        self.headers = {}
        self.body = Stream()
        self._chunked = False
        self._chunked_len = -2# this is special
        self._len = -1

    def read(self, msg):
        return self.handle(msg)

    def headers_handle(self, msg):
        while True:
            line = msg.readline()
            if None == line:
                return

            line = line.strip()
            if '' == line:
                self.handle = self.body_handle
                break

            self.raw_headers.append(line)
            key, value = utils.parse_http_header(line)
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
            line = msg.readline()
            chunk_size_end = cline.find(b';')
            if chunk_size_end < 0:
                chunk_size_end = len(cline)
                # skip chunk extension
            chunk_size_str = cline[0:chunk_size_end]
            if chunk_size_str[0] == b'0':
                return 0 # over

            try:
                chunk_len = int(chunk_size_str, 16)
                self._chunked_len = chunk_len
                return self.read_chunked_body(msg)
            except:
                pass


class HttpRequest(HttpStream):
    def __init__(self):
        self.reqline = {}
        self.raw_headers = []

        self.handle = self.reqline_handle


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
        if self.uri.startswith(b'http://') or self.uri.startswith(b'https://'):
            return self.uri
        else:
            return b'http://' + self.host + self.uri


class HttpResponse(HttpStream):
    def __init__(self):
        self.resline = {}
        self.content_len = 0

    def reqline_handle(self, msg):
        line = msg.readline()
        if not line:
            return

        items = line.split(' ')
        if len(items) < 2:
            return -1 # NOT HTTP

        self.raw_headers.append(line)
        self.reqline['status'] = items[1]
        self.handle = self.headers_handle


class HttpParser(httpparser):
    ERRNO_NUM     = 0
    ERRNO_NOTHTTP = 1
    """parse http req & resp"""
    def __init__(self, tcp):
        """
        :type processor: HttpDataProcessor
        """
        self.tcp = tcp
        self.errno = 0

        self.stream =  [String(), String()]
        self.handles = [None, None]

        self.msgs = []

        for msg in tcp.msgs:
            err = self.read_msg(*msg)
            if err:
                break

    def read_msg(self, http_type, data):
        stream = self.stream[http_type]
        rr = self.handles[http_type]

        stream.seek(0, 2)
        stream.write(data)

        if None == rr:
            stream.seek(0)
            line = stream.readline() # TODO maybe too big
            if not line:
                return

            if line[-8:-3].lower() == 'http/':
                rr = HttpRequest()
            elif line[0:5].lower() == 'http/'
                rr = HttpResponse()
            else:
                return self.ERRNO_NOTHTTP

            self.msgs.append(rr)
            self.handles[http_type] = rr

        stream.seek(0)
        res = rr.read(stream)
        if 0 == res:
            self.handles[http_type] = None
        return res

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
                if msg[0] == 0:
                    reqhdr = msg[1]

                    utils.print('  ' + reqhdr.method + ' ' + reqhdr.URI())
                    utils.print('\n')
        else:
            for i, msg in enumerate(self.msgs):
                if msg[0] == 0:
                    if i != 0:
                        utils.print('-' * 80)
                    reqhdr = msg[1]
                    utils.print(reqhdr.raw_data)
                    utils.print('\n')
                    utils.print('\n')
                else:
                    reshdr = msg[1]
                    utils.print(reshdr.raw_data)
                    utils.print('\n')
                    utils.print('\n')

