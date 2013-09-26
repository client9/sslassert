#!/usr/bin/env python

import requests
import urlparse
import sys
import re
import lxml
import lxml.html
import lxml.html.html5parser

apache_token_re = re.compile(r'<address>([^<]*)</address>')
generator_token_re = re.compile('<generator>([^<]*)</generator>')
apache_default_403 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN"><html><head><title>403 Forbidden</title></head><body><h1>Forbidden</h1><p>You don't have permission to access /wp-includes/"""

def wordpressfacts(url):
    original_parts = urlparse.urlsplit(url, scheme='http')
    parts = list(original_parts)
    parts[2] = '/'
    parts[3] = ''

    #
    # PHP Easter Eggs
    # http://php.net/?=PHPE9568F36-D428-11d2-A769-00AA001ACF42
    #
    newurl = urlparse.urlunsplit(parts)
    newurl += '?=PHPE9568F36-D428-11d2-A769-00AA001ACF42'
    req = requests.request('GET', newurl)

    egg = req.status_code == 200 and req.headers['content-type'].startswith('image')
    yield ('wordpress_php_easter-eggs', egg)
    yield ('wordpress_php_easter-eggs_status_code', req.status_code)
    yield ('wordpress_php_easter-eggs_content_type', req.headers['content-type'])

    yield ('wordpress_php_x-powered-by', req.headers.get('x-powered-by', None))

    parts[2] = '/wp-login.php'
    newurl = urlparse.urlunsplit(parts)
    req = requests.request('GET', newurl)
    yield ('workpress_wp-login_url', req.url)
    yield ('wordpress_wp-login_status-code', req.status_code)

    logins = list(urlparse.urlsplit(req.url))
    #if logins[0] == 'http':
    #    logins[0] = 'https'
    #req = requests.request('GET', urlparse.urlunsplit(logins))
    yield ('workpress_wp-login_url', req.url)

    tree = lxml.html.html5parser.fromstring(req.text)

    XHTML_NAMESPACE = "http://www.w3.org/1999/xhtml"
    form =tree.xpath("//h:form[@id='loginform']",
                     namespaces= {'h': XHTML_NAMESPACE})

    if len(form) == 1:
        formurl = form[0].get('action')
        fparts = urlparse.urlsplit(formurl, scheme = logins[0])

        yield ('wordpress_wp-login_action', formurl)
        yield ('wordpress_wp-login_method', form[0].get('method'))
        yield ('wordpress_wp-login_scheme', fparts[0])


    parts[2] = '/wp-includes/'
    parts[3] = ''
    newurl = urlparse.urlunsplit(parts)
    req = requests.request('GET', newurl)

    yield ('wordpress_wp-includes_status-code', req.status_code)

    text = req.content.replace("\n", '')
    default_text = apache_default_403 in text
    yield ('wordpress_wp-includes_apache-403-default', default_text)
    match = apache_token_re.search(req.text)
    if match:
        yield ('wordpress_wp-includes_apache_tokens', match.group(1))
    else:
        yield ('wordpress_wp-includes_apache_tokens', None)

    paths =  ('/wp-content/', '/wp-content/uploads/',
              '/wp-content/plugins/', '/wp-content/themes/')
    for path in paths:
        parts[2] = path
        newurl = urlparse.urlunsplit(parts)
        req = requests.request('GET', newurl)
        token = path.strip('/')
        token = token.replace('/', '-')

        yield ('wordpress_' + token + '_status-code', req.status_code)

        parts[2] = path + '.htaccess'
        newurl = urlparse.urlunsplit(parts)
        req = requests.request('GET', newurl)
        token += '-htaccess'
        yield ('wordpress_' + token + '_status-code', req.status_code)

    parts[2] = '/feed/'
    newurl = urlparse.urlunsplit(parts)
    req = requests.request('GET', newurl)
    match = generator_token_re.search(req.text)
    yield ('wordpress_feed_status_code', req.status_code)

    if match:
        yield ('wordpress_feed_version', match.group(1))
    else:
        yield ('wordpress_feed_version', None)

    #http://wordpress.org/?v=3.6</generator>
if __name__ == '__main__':
    url = sys.argv[1]
    for fact in wordpressfacts(url):
        print fact

