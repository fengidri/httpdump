from __future__ import unicode_literals, print_function, division

from collections import defaultdict

from pcapparser import utils
from pcapparser.constant import HttpType, Compress
from pcapparser.reader import DataReader
from pcapparser import config

from pcapparser.config import OutputLevel
from io import StringIO

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


__author__ = 'dongliu'

class HttpStream(object):
    def __init__(self):
        self.handle = None

    def read(self, msg):
        return self.handle(msg)

class HttpRequest(HttpStream):
    def __init__(self):
        self.method = b''
        self.host = b''
        self.uri = b''
        self.reqline = {}
        self.headers = {}
        self.transfer_encoding = b''
        self.content_encoding = b''
        self.content_type = b''
        self.compress = Compress.IDENTITY
        self.expect = b''
        self.protocol = b''


        self.handle = self.reqline_handle

        self._chunked = False
        self._len = -1

        self.raw_headers = []
        self.

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
        self.handle = self.request_handle

    def request_handle(self, msg):
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
        # handle the headrs over




    def URI(self):
        if self.uri.startswith(b'http://') or self.uri.startswith(b'https://'):
            return self.uri
        else:
            return b'http://' + self.host + self.uri


class HttpResponse(HttpStream):
    def __init__(self):
        self.content_len = 0
        self.status_line = None
        self.status_code = None
        self.transfer_encoding = b''
        self.content_encoding = b''
        self.content_type = b''
        self.compress = Compress.IDENTITY
        self.chunked = False
        self.connection_close = False
        self.raw_data = None


class httpparser(object):
    def read_headers(self, reader, lines):
        """
        :type reader: DataReader
        :type lines: list
        :return: dict
        """
        header_dict = defaultdict(str)
        while True:
            line = reader.read_line()
            if line is None:
                break
            line = line.strip()
            if not line:
                break
            lines.append(line)

            key, value = utils.parse_http_header(line)
            if key is None:
                # incorrect headers.
                continue

            header_dict[key.lower()] = value
        return header_dict

    def read_http_req_header(self, reader):
        """read & parse http headers"""
        line = reader.read_line()
        if line is None:
            return None
        line = line.strip()
        if not utils.is_request(line):
            return None

        req_header = HttpRequestHeader()
        items = line.split(b' ')
        if len(items) == 3:
            req_header.method = items[0]
            req_header.uri = items[1]
            req_header.protocol = items[2]

        lines = [line]
        header_dict = self.read_headers(reader, lines)
        if b"content-length" in header_dict:
            req_header.content_len = int(header_dict[b"content-length"])
        if b"transfer-encoding" in header_dict and b'chunked' in header_dict[b"transfer-encoding"]:
            req_header.chunked = True
        req_header.content_type = header_dict[b'content-type']
        req_header.compress = utils.get_compress_type(header_dict[b"content-encoding"])
        req_header.host = header_dict[b"host"]
        if b'expect' in header_dict:
            req_header.expect = header_dict[b'expect']

        req_header.raw_data = b'\n'.join(lines)
        return req_header

    def read_http_resp_header(self, reader):
        """read & parse http headers"""
        line = reader.read_line()
        if line is None:
            return line
        line = line.strip()

        if not utils.is_response(line):
            return None
        resp_header = HttpResponseHeader()
        resp_header.status_line = line
        try:
            resp_header.status_code = int(line.split(' ')[1])
        except:
            pass

        lines = [line]
        header_dict = self.read_headers(reader, lines)
        if b"content-length" in header_dict:
            resp_header.content_len = int(header_dict[b"content-length"])
        if b"transfer-encoding" in header_dict and b'chunked' in header_dict[b"transfer-encoding"]:
            resp_header.chunked = True
        resp_header.content_type = header_dict[b'content-type']
        resp_header.compress == utils.get_compress_type(header_dict[b"content-encoding"])
        resp_header.connection_close = (header_dict[b'connection'] == b'close')
        resp_header.raw_data = b'\n'.join(lines)
        return resp_header

    def read_chunked_body(self, reader, skip=False):
        """ read chunked body """
        result = []
        # read a chunk per loop
        while True:
            # read chunk size line
            cline = reader.read_line()
            if cline is None:
                # error occurred.
                if not skip:
                    return b''.join(result)
                else:
                    return
            chunk_size_end = cline.find(b';')
            if chunk_size_end < 0:
                chunk_size_end = len(cline)
                # skip chunk extension
            chunk_size_str = cline[0:chunk_size_end]
            # the last chunk
            if chunk_size_str[0] == b'0':
                # chunk footer header
                # TODO: handle additional http headers.
                while True:
                    cline = reader.read_line()
                    if cline is None or len(cline.strip()) == 0:
                        break
                if not skip:
                    return b''.join(result)
                else:
                    return
                    # chunk size
            chunk_size_str = chunk_size_str.strip()
            try:
                chunk_len = int(chunk_size_str, 16)
            except:
                return b''.join(result)

            data = reader.read(chunk_len)
            if data is None:
                # skip all
                # error occurred.
                if not skip:
                    return b''.join(result)
                else:
                    return
            if not skip:
                result.append(data)

            # a CR-LF to end this chunked response
            reader.read_line()

    def read_request(self, reader, message):
        """ read and output one http request. """
        if message.expect_header and not utils.is_request(reader.fetch_line()):
            req_header = message.expect_header
            message.expect_header = None
        else:
            req_header = self.read_http_req_header(reader)
            if req_header is None:
                # read header error, we skip all data.
                reader.skip_all()
                return
            if req_header.expect:
                # it is expect:continue-100 post request
                message.expect_header = req_header

        # deal with body
        if not req_header.chunked:
            content = reader.read(req_header.content_len)
        else:
            content = self.read_chunked_body(reader)

        _filter = config.get_filter()
        show = _filter.by_domain(req_header.host) and _filter.by_uri(req_header.uri)
        message.filtered = not show
        if show:
            self.msgs.append((0, req_header, content))

    def read_response(self, reader, message):
        """
        read and output one http response
        """
        resp_header = self.read_http_resp_header(reader)
        if resp_header is None:
            reader.skip_all()
            return

        if message.expect_header:
            if resp_header.status_code == 100:
                # expected 100, we do not read body
                reader.skip_all()
                return

        # read body
        if not resp_header.chunked:
            if resp_header.content_len == 0:
                if resp_header.connection_close:
                    # we can't get content length, so assume it till the end of data.
                    resp_header.content_len = 10000000
                else:
                    # we can't get content length, and is not a chunked body, we cannot do nothing,
                    # just read all data.
                    resp_header.content_len = 10000000
            content = reader.read(resp_header.content_len)
        else:
            content = self.read_chunked_body(reader)

        if not message.filtered:
            self.msgs.append((1, resp_header, content))


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

        self.stream =  [StringIO(), StringIO()]
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
        return rr.read(stream)

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

