#!/usr/bin/env python
import subprocess
import json
import datetime
import time
import sys
import logging
import urllib
import urlparse
from tornado import template
import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.wsgi
import tornado.escape
import tornado.options

from nmapfacts import nmapassert
from httpassert import httpfacts
#from sshassert import sshassert
from connect import sshfacts
from dnsassert import dnsfacts
from sslassert import sslassert
from wordpressfacts import wordpressfacts

class PageHandler(tornado.web.RequestHandler):
    def get(self, pagename):
        if pagename == '':
            pagename = 'home'

        self.render(
            pagename + '.html',
            title = pagename.replace('-',' '),
            ssl_protocol=self.request.headers.get('X-SSL-Protocol', ''),
            ssl_cipher=self.request.headers.get('X-SSL-Cipher', '')
        )

class FactHandler(tornado.web.RequestHandler):
    def get(self, engine, url):
        now = time.time()
        facts = {}
        facts['meta_timestamp'] = now
        if engine == 'home':
            self.render(
                pagename + '.html',
                title = pagename.replace('-',' '),
                ssl_protocol=self.request.headers.get('X-SSL-Protocol', ''),
                ssl_cipher=self.request.headers.get('X-SSL-Cipher', '')
            )
        elif engine == 'http':
            if not url.startswith('http'):
                url = 'http://' + url
            for k,v in httpfacts(url):
                facts[k] = v
        elif engine == 'ports':
            parts = urlparse.urlparse(url)
            if parts.scheme == '':
                url = 'https://' + url
                parts = urlparse.urlparse(url)
            host = parts.netloc
            s = nmapassert()
            for k,v in s.smoke(host):
                facts[k] = v
        elif engine == 'ssl':
            parts = urlparse.urlparse(url)
            if parts.scheme == '':
                url = 'https://' + url
                parts = urlparse.urlparse(url)
            host = parts.netloc
            if parts.path == '':
                path = '/'
            else:
                path = parts.path
            s = sslassert()
            # need to fix in sslassert test
            tmpdict = s.test(host, path)
            if tmpdict is not None:
                for k,v in tmpdict.iteritems():
                    facts[k] = v
        elif engine == 'dns':
            parts = urlparse.urlparse(url)
            if parts.scheme == '':
                url = 'http://' + url
                parts = urlparse.urlparse(url)
            host = parts.netloc
            for k,v in dnsfacts(host):
                facts[k] = v
        elif engine == 'wordpress':
            parts = urlparse.urlparse(url)
            if parts.scheme == '':
                url = 'http://' + url
            for k,v in wordpressfacts(url):
                facts[k] = v
        elif engine == 'ssh':
            parts = urlparse.urlparse(url)
            if parts.scheme == '':
                url = 'https://' + url
                parts = urlparse.urlparse(url)
            host = parts.netloc
            jsontext = subprocess.check_output(['./connect.py', host])
            facts = json.loads(jsontext)

        facts['meta_duration'] = time.time() - now
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(facts, indent=2, sort_keys=True))

import os
settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "static"),
    "template_path": os.path.join(os.path.dirname(__file__), "."),
    "xsrf_cookies": True,
    "gzip": False
}

application = tornado.web.Application([
    (r"/facts/([a-z]+)/(.*)", FactHandler),
    (r'/robots.txt', tornado.web.StaticFileHandler, {'path': os.path.join(os.path.dirname(__file__), "static")}),
    (r'/favicon.ico', tornado.web.StaticFileHandler, {'path': os.path.join(os.path.dirname(__file__), "static")}),
    (r"/([a-z-]*)", PageHandler)
    ], **settings)

if __name__ == "__main__":
    tornado.options.parse_command_line()

    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(process)d %(message)s")
    server = tornado.httpserver.HTTPServer(application)
    server.bind(8888)
    server.start(2)
    tornado.ioloop.IOLoop.instance().start()
