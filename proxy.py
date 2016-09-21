#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging
import socket
import struct

import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
from tornado import gen, httpclient, tcpclient, httputil, tcpserver
from tornado.options import options, define

import common

define('http-port', default=8080, type=int, help="http listen port")
define('port', default=8888, type=int, help="socks listen port")

SOCKS5_VERSION = 5

# SOCKS METHOD definition
SOCKS5_METHOD_NO_AUTH = 0
SOCKS5_METHOD_NOTHING = 0xFF

# SOCKS command definition
SOCKS5_CMD_CONNECT = 1
SOCKS5_CMD_BIND = 2
SOCKS5_CMD_UDP_ASSOCIATE = 3

# SOCKS address type
SOCKS5_ADDRESS_TYPE_IPV4 = 0x01
SOCKS5_ADDRESS_TYPE_IPV6 = 0x04
SOCKS5_ADDRESS_TYPE_HOST = 0x03
SOCKS5_ADDRESS_TYPE_AUTH = 0x10
SOCKS5_ADDRESS_TYPE_MASK = 0xF


class SSHttpProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def __init__(self, *args, **kwargs):
        super(SSHttpProxyHandler, self).__init__(*args, **kwargs)
        self.upstream = None
        self.client = None

    def handle_response(self, response):
        if response.error and not isinstance(response.error, tornado.httpclient.HTTPError):
            self.set_status(500)
            self.write('Internal server error:\n' + str(response.error))
        else:
            self.set_status(response.code, response.reason)

            for header, v in response.headers.get_all():
                if header not in ('Content-Length', 'Transfer-Encoding', 'Content-Encoding', 'Connection'):
                    self.add_header(header, v)  # some header appear multiple times, eg 'Set-Cookie'

            if response.body:
                self.set_header('Content-Length', len(response.body))
                self.write(response.body)
        self.finish()

    @gen.coroutine
    def get_or_post_method(self):
        logging.info('http request from %s to %s %s',
                     self.request.remote_ip, self.request.method, self.request.uri)
        try:
            if 'Proxy-Connection' in self.request.headers:
                del self.request.headers['Proxy-Connection']
            req = httpclient.HTTPRequest(self.request.uri,
                                         method=self.request.method,
                                         body=self.request.body,
                                         headers=self.request.headers,
                                         follow_redirects=False,
                                         allow_nonstandard_methods=True)
            client = httpclient.AsyncHTTPClient()
            response = yield client.fetch(req, raise_error=False)
            self.handle_response(response)
        except tornado.httpclient.HTTPError as e:
            logging.debug(e)
            if hasattr(e, 'response') and e.response:
                self.handle_response(e.response)
            else:
                self.set_status(500)
                self.write('Internal server error:\n' + str(e))
                self.finish()
    @gen.coroutine
    def get(self):
        yield self.get_or_post_method()

    @gen.coroutine
    def post(self):
        yield self.get_or_post_method()

    @tornado.web.asynchronous
    def connect(self):
        logging.info('start connect to %s from %s:%d',
                     self.request.uri,
                     self.request.connection.context.address[0],
                     self.request.connection.context.address[1])

        host, port = httputil.split_host_and_port(self.request.uri)
        self.start_tunnel(host, port)

    def client_close(self, data=None):
        logging.debug('%s client closing', self.request.uri)
        if self.upstream.closed():
            return
        if data:
            self.upstream.write(data)
        self.upstream.close()

    def upstream_close(self, data=None):
        logging.debug("%s upstream closing", self.request.uri)
        if self.client.closed():
            return
        if data:
            self.client.write(data)
        self.client.close()
    @gen.coroutine
    def start_tunnel(self, host, port):
        try:
            self.client = self.request.connection.detach()
            self.upstream = yield tcpclient.TCPClient().connect(host, port)
        except:
            logging.warning("connect to %s failed", self.request.uri)
            raise gen.Return()
        self.client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')
        self.client.read_until_close(self.client_close, streaming_callback=self.upstream.write)
        self.upstream.read_until_close(self.upstream_close, streaming_callback=self.client.write)


class StreamChannel(object):
    def __init__(self, stream, address):
        self.local_address = address
        self.local_stream = stream
        self.remote_address = None
        self.remote_stream = None
        # self.local_stream = tornado.iostream.IOStream()
        # self.remote_stream = tornado.iostream.IOStream()
        future = self.start()
        tornado.ioloop.IOLoop.instance().add_future(future, callback=lambda f: f.result())

    def __hash__(self):
        return id(self)

    @gen.coroutine
    def start(self):
        try:
            r = yield self.socks5_auth()
            if not r:
                self.destroy()
                raise gen.Return()

            r = yield self.socks5_request()
            if not r:
                self.destroy()
                raise gen.Return()
        except:
            logging.warning("SOCKS stream failed")
            self.destroy()
            raise gen.Return()
        self.start_channel()

    def _read_from_local(self, data):
        if self.remote_stream.closed():
            self.destroy()
        else:
            self.remote_stream.write(data)

    def _read_from_remote(self, data):
        if self.local_stream.closed():
            self.destroy()
        else:
            self.local_stream.write(data)

    @gen.coroutine
    def start_channel(self):
        logging.info("connect to %s:%d from %s:%d",
                     self.remote_address[0], self.remote_address[1],
                     self.local_address[0], self.local_address[1])
        try:
            self.remote_stream = yield tcpclient.TCPClient().connect(host=self.remote_address[0],
                                                                     port=self.remote_address[1])
        except IOError:
            logging.warning("connect %s:%d failed", self.remote_address[0], self.remote_address[1])
            self.destroy()
            raise gen.Return()
        try:
            yield [self.local_stream.read_until_close(streaming_callback=self._read_from_local),
                   self.remote_stream.read_until_close(streaming_callback=self._read_from_remote)]
            self.destroy()
        except tornado.iostream.StreamClosedError:
            logging.warning("stream is closed")

    @gen.coroutine
    def socks5_auth(self):
        # | version | nmethods | methods  |
        # |---------+----------+----------|
        # |       1 |        1 | 1 to 255 |
        data = yield self.local_stream.read_bytes(257, partial=True)
        if len(data) < 3:
            logging.warning('method selection header too short')
            raise gen.Return(False)

        socks_version = common.ord(data[0])
        n_methods = common.ord(data[1])
        if socks_version != SOCKS5_VERSION:
            logging.warning('unsupported SOCKS protocol version ' + str(socks_version))
            raise gen.Return(False)
        if n_methods < 1:
            raise gen.Return(False)
        no_auth_exist = False

        methods = data[2:]
        for method in methods:
            if common.ord(method) == SOCKS5_METHOD_NO_AUTH:
                no_auth_exist = True
                break
        if not no_auth_exist:
            logging.warning('none of SOCKS METHOD\'s requested by client is supported')
            raise gen.Return(False)
        else:
            self.local_stream.write(b'\x05\00')
            raise gen.Return(True)

    @gen.coroutine
    def socks5_request(self):
        # request:
        # | VER | CMD | RSV   | ATYP | DST.ADDR | DST.PORT |
        # |-----+-----+-------+------+----------+----------|
        # |  1  |  1  | X'00' |   1  | Variable |    2     |

        # response:
        # | VER | REP | RSV   | ATYP | BND.ADDR | BND.PORT |
        # |-----+-----+-------+------+----------+----------|
        # |   1 |   1 | X'00' |    1 | Variable |        2 |

        data = yield self.local_stream.read_bytes(4)
        socks_version = common.ord(data[0])
        if socks_version != SOCKS5_VERSION:
            logging.warning('unsupported SOCKS protocol version ' + str(socks_version))
            raise gen.Return(False)
        command = common.ord(data[1])
        if command == SOCKS5_CMD_UDP_ASSOCIATE:
            logging.debug("SOCKS udp request is not supported")
            # if self.local_stream.socket.family == socket.AF_INET6:
            #     self.local_stream.write(b"\x05\x07\x00\x04\x00\xff\xff")
            # elif self.local_stream.socket.family == socket.AF_INET:
            #     self.local_stream.write(b"\x05\x07\x00\x04\x00\xff\xff")
            self.local_stream.write(b"\x05\x07\x00\x01"
                                    b"\x00\x00\x00\x00\x10\x10")
            raise gen.Return(False)
        elif command == SOCKS5_CMD_BIND:
            logging.debug("SOCKS bing command is not supported")
            self.local_stream.write(b"\x05\x07\x00\x03\x00\xff\xff")
            raise gen.Return(False)
        elif command != SOCKS5_CMD_CONNECT:
            logging.debug("unsupported SOCKS request " + str(command))
            raise gen.Return(False)
        address_type = common.ord(data[3]) & SOCKS5_ADDRESS_TYPE_MASK
        dest_addr = None
        dest_port = None
        if address_type == SOCKS5_ADDRESS_TYPE_IPV4:
            # DST.ADDR :4 | DST.PORT | 2
            data = yield self.local_stream.read_bytes(6)
            dest_addr = socket.inet_ntoa(data[:4])
            dest_port = struct.unpack("!H", data[:4])[0]
        elif address_type == SOCKS5_ADDRESS_TYPE_IPV6:
            # DST.ADDR :16 | DST.PORT | 2
            data = yield self.local_stream.read_bytes(18)
            dest_addr = common.inet_ntop(socket.AF_INET6, data[:16])
            dest_port = struct.unpack("!H", data[16:])[0]
        elif address_type == SOCKS5_ADDRESS_TYPE_HOST:
            # ADDR.LEN:1 | DST.ADDR:ADDR.LEN | DST.PORT:2
            _len = yield self.local_stream.read_bytes(1)
            _len = common.ord(_len)
            if _len <= 0 or _len > 128:
                raise gen.Return(False)
            data = yield self.local_stream.read_bytes(_len + 2)
            dest_addr = data[:_len]
            dest_port = struct.unpack("!H", data[_len:])[0]
        self.local_stream.write(b'\x05\x00\x00\x01'
                                b'\x00\x00\x00\x00\x10\x10'),
        if not dest_addr or not dest_port:
            logging.warning("unsupported addrtype %d", address_type)
            raise gen.Return(False)
        self.remote_address = dest_addr, dest_port
        raise gen.Return(True)

    def destroy(self):
        if self.local_stream:
            logging.debug("destroying local stream")
            self.local_stream.close()
            self.local_stream = None

        if self.remote_stream:
            logging.debug("destroying remote stream")
            self.remote_stream.close()
            self.remote_stream = None


class SSSocksProxy(tcpserver.TCPServer):
    def __init__(self, *args, **kwargs):
        super(SSSocksProxy, self).__init__(*args, **kwargs)

    def handle_stream(self, stream, address):
        StreamChannel(stream, address)

if __name__ == '__main__':
    options.parse_command_line()
    logging.info("Starting proxy SOCKS5(%d) HTTP(%d)",
                 options.port,
                 options.http_port)
    # http
    app = tornado.web.Application([ (r'.*', SSHttpProxyHandler), ])
    app.listen(options.http_port)
    # socks
    server = SSSocksProxy()
    server.listen(options.port)
    loop = tornado.ioloop.IOLoop.instance()
    loop.start()
