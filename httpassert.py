#!/usr/bin/env python

import requests
import calendar
import time
from lxml.html import tostring, html5parser
import lxml.objectify

months = {
    'Jan':'01',
    'Feb':'02',
    'Mar':'03',
    'Apr':'04',
    'May':'05',
    'Jun':'06',
    'Jul':'07',
    'Aug':'08',
    'Sep':'09',
    'Oct':'10',
    'Nov':'11',
    'Dec':'12'
}
def http_parse_date(datestr):
    """
    Sat, 07 Sep 2013 23:34:48 GMT
    01234567890123456789012345678
    """
    try:
        elems = (
            datestr[12:16],
            months[datestr[8:11]],
            datestr[5:7],
            datestr[17:19],
            datestr[20:22],
            datestr[23:25],
        )
        return calendar.timegm( [ int(i) for i in elems] )
    except:
        return 0

def httpfacts(url, now=None):
    if now is None:
        now = int(time.time())

    req = requests.request('TRACE', url)
    yield ('http_trace_status-code', req.status_code)

    req = requests.request('OPTIONS', url)
    yield ('http_options_status-code', req.status_code)

    req = requests.request('GET', url)

    yield ('http_header_status-code', req.status_code)
    for k,v in req.headers.iteritems():
        yield ('http_header_' + k, v)
        if k == 'date' or k == 'last-modified' or k == 'expires':
            ts = http_parse_date(v)
            yield ('http_header_' + k + '_timestamp', http_parse_date(v))
            yield ('http_header_' + k + '_delta', ts - now)

    for k in req.cookies:
        """
Cookie(version=0, name='NID', value='67=Gx1dRLtNcYAkrXO8y3chpipEIQO4-PeWDuQ48QqjwZndKfJCQqvrdElss8vyDA_5wqohA1twy2te7xZqV9AvQVOmWElZJEcFu7VERLrr_tUlwlooIaDyb_UgqZy4zg-3', port=None, port_specified=False, domain='.google.co.jp', domain_specified=True, domain_initial_dot=True, path='/', path_specified=True, secure=False, expires=1393118966, discard=False, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
        """

        prefix = 'http_cookie_' + k.name
        yield (prefix, k.value)
        yield (prefix + '_path', k.path)
        yield (prefix + '_domain', k.domain)
        yield (prefix + '_secure', k.secure)
        yield (prefix + '_expires', k.expires)
        yield (prefix + '_version', k.version)
        yield (prefix + '_rfc2109', k.rfc2109)
        httponly = k.has_nonstandard_attr('HttpOnly')
        yield (prefix + '_httponly', httponly)

    tree = html5parser.fromstring(req.text)

    #for el in tree.iterdescendants('meta'):
    XHTML_NAMESPACE = "http://www.w3.org/1999/xhtml"
    XHTML = "{%s}" % XHTML_NAMESPACE

    # really look for HMTL/HEAD
    yield ('html_root_tag', str(tree.tag))
    #yield ('html_root1_tag', str(tree[0].tag))

    # find HEAD element
    #  /html/head[0]
    head = None
    for child in tree.iter(XHTML + 'head'):
        head = child
        break
    if head is None:
        return

    for meta in head.iterchildren(XHTML + 'meta'):
        if meta.get('name') and meta.get('content') is not None:
            yield 'html_meta_name_' + meta.get('name'), meta.get('content')
        elif meta.get('name') and meta.get('value') is not None:
            yield 'html_meta_name_' + meta.get('name'), meta.get('value')
        elif meta.get('property') and meta.get('content') is not None:
            yield 'html_meta_property_' + meta.get('property'), meta.get('content')
        elif meta.get('http-equiv') and meta.get('content') is not None:
            yield 'html_meta_http-equiv_' + meta.get('http-equiv').lower(), meta.get('content')
        elif meta.get('charset') is not None:
            yield 'html_meta_charset', meta.get('charset').lower()
        else:
            yield 'html_meta_unknown', tostring(meta)

        #for name, value in sorted(meta.items()):
        #    print('%s = %r' % (name, value))
        #print '--'
    #print req.text

if __name__ == '__main__':
    import sys
    import json
    import time
    target = sys.argv[1]
    tl = target.lower()
    if not (tl.startswith('http://') or tl.startswith('https://')):
        target = 'http://' + target

    facts = {
        'meta_target': target,
        'meta_timestamp': int(time.time())
    }
    for k,v in httpfacts(target):
        facts[k] = v

    output = { sys.argv[1]: facts}

    print json.dumps(output, indent=2, sort_keys=True)


