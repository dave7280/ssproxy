#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging

import tornado.httpserver
import tornado.ioloop
import tornado.iostream
import tornado.web
from tornado import gen, httpclient, tcpclient, httputil
from tornado.options import options, define

define('port', default=8888, type=int, help="listen port")

__all__ = ['SSProxyHandler', 'ss_run_proxy']


def fetch_request(url, callback, **kwargs):
    req = tornado.httpclient.HTTPRequest(url, **kwargs)
    client = tornado.httpclient.AsyncHTTPClient()
    client.fetch(req, callback, raise_error=False)


class SSProxyHandler(tornado.web.RequestHandler):
    SUPPORTED_METHODS = ['GET', 'POST', 'CONNECT']

    def __init__(self, *args, **kwargs):
        super(SSProxyHandler, self).__init__(*args, **kwargs)
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
    def get(self):
        logging.info('Handle request from %s to %s %s',
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
    def post(self):
        yield self.get()

    @tornado.web.asynchronous
    def connect(self):
        logging.info('Start CONNECT to %s from %s', self.request.uri, self.request.remote_ip)
        # host, port = self.request.uri.split(':')
        host, port = httputil.split_host_and_port(self.request.uri)
        self.client = self.request.connection.stream
        c = tcpclient.TCPClient()
        future = c.connect(host, port)
        tornado.ioloop.IOLoop.current().add_future(future, self.start_tunnel)

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

    def start_tunnel(self, future):
        self.upstream = future.result()
        logging.debug('CONNECT tunnel established to %s', self.request.uri)
        self.client.read_until_close(self.client_close, self.upstream.write)
        self.upstream.read_until_close(self.upstream_close, self.client.write)
        self.client.write(b'HTTP/1.0 200 Connection established\r\n\r\n')


def ss_run_proxy(port, start_ioloop=True):
    app = tornado.web.Application([
        (r'.*', SSProxyHandler),
    ])
    app.listen(port)
    ioloop = tornado.ioloop.IOLoop.instance()
    if start_ioloop:
        ioloop.start()


if __name__ == '__main__':
    options.parse_command_line()
    print ("Starting HTTP proxy on port %d" % options.port)
    ss_run_proxy(options.port)
