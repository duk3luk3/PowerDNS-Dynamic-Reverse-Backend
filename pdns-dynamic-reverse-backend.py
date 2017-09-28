#!/usr/bin/env python
#
"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:

launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper
pipe-timeout=500

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
import sys, os
import re
import syslog
import time
import netaddr
import IPy
import radix
import yaml
from functools import partial


class HierDict(dict):
    def __init__(self, parent=None, default=None):
        self._parent = parent
        if default != None:
            self.update(default)

    def __getitem__(self, name):
        try:
            return super(HierDict,self).__getitem__(name)
        except KeyError, e:
            if self._parent is None:
                raise
            return self._parent[name]

DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'
CONFIG = 'dynrev.yml'

def base36encode(n):
    s = ''
    while True:
        n, r = divmod(n, len(DIGITS))
        s = DIGITS[r] + s
        if n == 0:
            break
    return s

def base36decode(s):
    n, s = 0, s[::-1]
    for i in xrange(0, len(s)):
        r = DIGITS.index(s[i])
        n += r * (len(DIGITS) ** i)
    return n


def print_log(set_loglevel, do_syslog, out, loglevel, msg, *args):
    if do_syslog:
        syslog.syslog('=%d= %s' % (loglevel, logmsg))
    if set_loglevel >= loglevel:
        logmsg = 'LOG\t' + msg % tuple(args)
        print >>out, logmsg

def print_data(set_loglevel, do_syslog, out, msg='', *args, **kwargs):
    verb = kwargs.get('verb', 'DATA')
    if len(msg) > 0:
        answer = '%s\t' % (verb)  + msg % tuple(args)
    else:
        answer = verb
    if verb != 'OK':
        print_log(set_loglevel, do_syslog, out, 3, answer)
    if do_syslog:
        syslog.syslog('>>>  ' + answer)
    print >>out, answer

def parse(prefixes, rtree, args, fd, out):
    if args.syslog:
        syslog.openlog(os.path.basename(sys.argv[0]), syslog.LOG_PID)

    log = partial(print_log, args.loglevel, args.syslog, out)
    data = partial(print_data, args.loglevel, args.syslog, out)
    line = fd.readline().strip()
    if args.syslog:
        syslog.syslog('<<< ' + line)
    if not line.startswith('HELO'):
        data('FAIL')
        out.flush()
        sys.exit(1)
    else:
        data('%s ready with %d prefixes configured, loglevel %d', os.path.basename(sys.argv[0]), len(prefixes), args.loglevel, verb='OK')
        out.flush()

    log(5, 'prefixes: %s', prefixes)

    lastnet=0
    while True:
        line = fd.readline().strip()
        if not line:
            break

        log(3, 'QERY\t%s', line)
        if args.syslog:
            syslog.syslog('<<< ' + line)

        request = line.split('\t')
        if request[0] == 'AXFR':
            if not lastnet == 0:
                data('%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600',
                        lastnet['forward'], 'IN', lastnet['ttl'], qid, lastnet['dns'], lastnet['email'], time.strftime('%Y%m%d%H'))
                lastnet=lastnet
                for ns in lastnet['nameserver']:
                    data('%s\t%s\tNS\t%d\t%s\t%s',
                            lastnet['forward'], 'IN', lastnet['ttl'], qid, ns)
            data(verb='END')
            out.flush()
            continue
        if len(request) < 6:
            log(1, 'PowerDNS sent unparsable line')
            data(verb='END')
            out.flush()
            continue


        (kind, qname, qclass, qtype, qid, ip), rest = request[:6], request[6:]

        if len(rest) > 0:
            their_ip = rest[0]

        log(4, 'Parsed query: qname=%s, qtype=%s, qclass=%s, qid=%s, ip=%s', qname, qtype, qclass, qid, ip)

        if qtype in ['AAAA', 'ANY']:
            log(5, 'Processing %s Query for AAAA', qtype)
            for range, key in prefixes.iteritems():
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 6 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        ipv6 = netaddr.IPAddress(long(range.value) + long(node))
                        data('%s\t%s\tAAAA\t%d\t%s\t%s', qname, qclass, key['ttl'], qid, ipv6)
                        break
        if qtype in ['A', 'ANY']:
            log(5, 'Processing %s Query for %s for qtype A', qtype, qname)
            for range, key in prefixes.iteritems():
                log(5, 'checking if qname.endswith %s and qname.startswith %s', key['forward'], key['prefix'])
                if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 4 and qname.startswith(key['prefix']):
                    node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
                    try:
                        node = base36decode(node)
                    except ValueError:
                        node = None
                    if node:
                        log(5, 'Decoded node %s, in range %s / %s', node, range, range.value)
                        ipv4 = netaddr.IPAddress(long(range.value) + long(node))
                        data('%s\t%s\tA\t%d\t%s\t%s', qname, qclass, key['ttl'], qid, ipv4)
                        break

        if qtype in ['PTR', 'ANY'] and qname.endswith('.ip6.arpa'):
            log(5, 'Processing %s Query for ip6 PTR', qtype)
            ptr = qname.split('.')[:-2][::-1]
            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in xrange(0, len(ptr), 4))
            try:
                ipv6 = netaddr.IPAddress(ipv6)
            except:
                ipv6 = netaddr.IPAddress('::')
            node=rtree.search_best(str(ipv6))
            if node:
                range, key = node.data['prefix'], prefixes[node.data['prefix']]
                node = ipv6.value - range.value
                node = base36encode(node)
                data('%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s',
                    qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward'])

        if qtype in ['PTR', 'ANY'] and qname.endswith('.in-addr.arpa'):
            log(5, 'Processing %s Query for in-addr PTR', qtype)
            ptr = qname.split('.')[:-2][::-1]
            ipv4='.'.join(''.join(ptr[x:x+1]) for x in xrange(0, len(ptr), 1))
            try:
                ipv4 = netaddr.IPAddress(ipv4)
            except:
                ipv4 = netaddr.IPAddress('127.0.0.1')
            node=rtree.search_best(str(ipv4))
            if node:
                range, key = node.data['prefix'], prefixes[node.data['prefix']]
                node = ipv4.value - range.value
                node = base36encode(node)
                data('%s\t%s\tPTR\t%d\t%s\t%s%s%s.%s',
                    qname, qclass, key['ttl'], qid, key['prefix'], node, key['postfix'], key['forward'])


        if qtype in ['SOA', 'ANY', 'NS']:
            log(5, 'Processing %s Query for SOA/NS', qtype)
            for range, key in prefixes.iteritems():
                log(5, 'Checking domain %s <> %s', key['domain'], qname)
                if qname == key['domain']:
                    if not qtype == 'NS':
                        data('%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600',
                                key['domain'], qclass, key['ttl'], qid, key['dns'], key['email'], time.strftime('%Y%m%d%H'))
                        lastnet=key
                    if qtype in ['ANY', 'NS']:
                        for ns in key['nameserver']:
                            data('%s\t%s\tNS\t%d\t%s\t%s', key['domain'], qclass, key['ttl'], qid, ns)
                    break
                elif qname == key['forward']:
                    if not qtype == 'NS':
                        data('%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600',
                                key['forward'], qclass, key['ttl'], qid, key['dns'], key['email'], time.strftime('%Y%m%d%H'))
                        lastnet=key
                    if qtype in ['ANY', 'NS']:
                        for ns in key['nameserver']:
                            data('%s\t%s\tNS\t%d\t%s\t%s', key['forward'], qclass, key['ttl'], qid, ns)
                    break

        data(verb='END')
        out.flush()

    return 0


def parse_config(config_path):

    with open(config_path) as config_file:
        config_dict = yaml.load(config_file)

    defaults = config_dict.get('defaults', {})
    prefixes = { netaddr.IPNetwork(prefix) : HierDict(defaults, info) for prefix, info in config_dict['prefixes'].items()}

    new_prefixes = {}

    for zone in prefixes:
        if not prefixes[zone].has_key('domain'):
            from IPy import IP
            revNames = IP(str(zone.cidr)).reverseNames()
            if len(revNames) == 1:
                prefixes[zone]['domain']=revNames[0][:-1]
                new_prefixes[zone] = prefixes[zone]
            elif zone.version == 4:
                for revName in revNames:
                    splitter = '.' if zone.version == 4 else ':'
                    fwName = revName.split(splitter)[-4::-1]
                    prefixlen = len(fwName) * 8
                    newZone = netaddr.IPNetwork(splitter.join(fwName) + '/' + str(prefixlen))
                    new_prefixes[newZone] = HierDict(prefixes[zone], {'domain': revName[:-1], 'prefix': prefixes[zone]['prefix'] + fwName[-1] + '-'})
            else:
                raise Exception('Version 6 zone should not have multiple reverse zones')
        else:
            new_prefixes[zone] = prefixes[zone]

    prefixes = new_prefixes

    rtree=radix.Radix()

    for prefix in prefixes.keys():
        node=rtree.add(str(prefix))
        node.data['prefix']=prefix

    return prefixes, rtree


if __name__ == '__main__':
    import sys
    import argparse

    parser = argparse.ArgumentParser(description='Resolve DNS pool zones compliant to PowerDNS Pipe Backend ABI version 1')
    parser.add_argument('-c', '--config', default=CONFIG, help='Configuration file path')
    parser.add_argument('-l', '--loglevel', default=1, type=int, help='log level - 1: Warn, 2: Info, 3: Responses, 4: Debug, 5: Verbose')
    parser.add_argument('-s', '--syslog', action='store_true', default=False, help='Log to syslog - useful for debugging protocol issues')

    args = parser.parse_args()

    prefixes, rtree = parse_config(args.config)
    sys.exit(parse(prefixes, rtree, args, sys.stdin, sys.stdout))
