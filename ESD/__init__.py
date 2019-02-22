# -*- coding: utf-8 -*-

"""
    ESD
    ~~~

    Implements enumeration sub domains

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/ESD
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import os
import re
import sys
import time
import ssl
import math
import string
import random
import traceback
import itertools
import datetime
import colorlog
import asyncio
import uvloop
import aiodns
import aiohttp
import logging
import requests
import backoff
import socket
import async_timeout
import dns.query
import dns.zone
import dns.resolver
import multiprocessing
import threading
import urllib.parse as urlparse
import urllib.parse as urllib
from collections import Counter
from aiohttp.resolver import AsyncResolver
from itertools import islice
from difflib import SequenceMatcher

__version__ = '0.0.21'

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

handler = colorlog.StreamHandler()
formatter = colorlog.ColoredFormatter(
    '%(log_color)s%(asctime)s [%(name)s] [%(levelname)s] %(message)s%(reset)s',
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
)
handler.setFormatter(formatter)

logger = colorlog.getLogger('ESD')
logger.addHandler(handler)
logger.setLevel(logging.INFO)

#shadowsocks代理
proxies = {
    "http": "socks5h://127.0.0.1:1080",
    "https": "socks5h://127.0.0.1:1080",
    }

ssl.match_hostname = lambda cert, hostname: True

class DNSTransfer(object):
    def __init__(self, domain):
        self.domain = domain

    def transfer_info(self):
        ret_zones = list()
        try:
            nss = dns.resolver.query(self.domain, 'NS')
            nameservers = [str(ns) for ns in nss]
            ns_addr = dns.resolver.query(nameservers[0], 'A')
            # dnspython 的 bug，需要设置 lifetime 参数
            zones = dns.zone.from_xfr(dns.query.xfr(ns_addr, self.domain, relativize=False, timeout=2, lifetime=2), check_origin=False)
            names = zones.nodes.keys()
            for n in names:
                subdomain = ''
                for t in range(0, len(n) - 1):
                    if subdomain != '':
                        subdomain += '.'
                    subdomain += str(n[t].decode())
                if subdomain != self.domain:
                    ret_zones.append(subdomain)
            return ret_zones
        except:
            return []


class CAInfo(object):
    def __init__(self, domain):
        self.domain = domain

    def dns_resolve(self):
        padding_domain = 'www.' + self.domain
        # loop = asyncio.get_event_loop()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        resolver = aiodns.DNSResolver(loop=loop)
        f = resolver.query(padding_domain, 'A')
        result = loop.run_until_complete(f)
        return result[0].host

    def get_cert_info_by_ip(self, ip):
        s = socket.socket()
        s.settimeout(2)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        cert_path = base_dir + '/cacert.pem'
        connect = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=cert_path)
        connect.settimeout(2)
        connect.connect((ip, 443))
        cert_data = connect.getpeercert().get('subjectAltName')
        return cert_data

    def get_ca_domain_info(self):
        domain_list = list()
        try:
            ip = self.dns_resolve()
            cert_data = self.get_cert_info_by_ip(ip)
        except Exception as e:
            return domain_list

        for domain_info in cert_data:
            hostname = domain_info[1]
            if not hostname.startswith('*') and hostname.endswith(self.domain):
                domain_list.append(hostname)

        return domain_list

    def get_subdomains(self):
        subs = list()
        subdomain_list = self.get_ca_domain_info()
        for sub in subdomain_list:
            subs.append(sub[:len(sub) - len(self.domain) - 1])
        return subs

class EngineBase(multiprocessing.Process):
    def __init__(self,base_url,domain,q,verbose):
        multiprocessing.Process.__init__(self)
        self.lock = threading.Lock()
        self.q = q
        self.subdomains = []
        self.base_url = base_url
        self.domain = domain
        self.session = requests.Session()
        self.headers = {
              'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
              'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.8',
              'Accept-Encoding': 'gzip',
        }
        self.timeout = 30
        self.verbose = verbose
        

    def get_page(self, num):
        return num + 10

    #应当在子类里重写
    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_pages(self,num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    def send_req(self, page_no=1):
        url = self.base_url.format(domain=self.domain, page_no=page_no)
        try:
            resp = self.session.get(url, headers=self.headers, timeout=self.timeout)
        except Exception:
            resp = None
        
        return self.get_response(resp)

    def enumerate(self):
        flag = True
        page_no = 0
        prev_links = []
        retries = 0

        while flag:
            if self.check_max_pages(page_no):
                return self.subdomains
            resp = self.send_req(page_no)

            if not self.check_response_errors(resp):
                return self.subdomains
            links = self.extract_domains(resp)

            if links == prev_links:
                retries += 1
                page_no = self.get_page(page_no)

                if retries >= 3:
                    return self.subdomains

            prev_links = links
            self.should_sleep()

        return self.subdomains

    def run(self):
        domain_list = self.enumerate()
        for domain in domain_list:
            self.q.append(domain)


class Google(EngineBase):
    def __init__(self, domain, q, verbose):
        base_url = "https://www.google.com/search?q=site:{domain}+-www.{domain}&start={page_no}"
        super(Google,self).__init__(base_url,domain,q,verbose)
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        self.engine_name = 'Google'

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<cite.*?>(.*?)<\/cite>')
        try:
            links_list = link_regx.findall(resp)
            for link in links_list:
                link = re.sub('<span.*>', '', link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    logger.info('{engine_name}: {subdomain}'.format(engine_name=self.engine_name, subdomain=subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        return links_list

    def check_response_errors(self, resp):
        if isinstance(resp,int):
            logger.warning("Please use proxy to access Google!")
            logger.warning("Finished now the Google Enumeration ...")
            return False
        return True

    def send_req(self, page_no=1):
        url = self.base_url.format(domain=self.domain, page_no=page_no)
        try:
            #因为众所周知的原因，访问yahoo和Google需要使用代理，这里我使用了自己ss
            resp = self.session.get(url,proxies=proxies,headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None
        
        return self.get_response(resp)


class Bing(EngineBase):
    def __init__(self, domain, q, verbose):
        base_url = 'https://www.bing.com/search?q=domain%3A{domain}%20-www.{domain}&go=Submit&first={page_no}'
        super(Bing,self).__init__(base_url,domain,q,verbose)
        self.MAX_PAGES = 30
        self.engine_name = 'Bing'

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile('<li class="b_algo"><div class="b_title"><h2><a target="_blank" href="(.*?)"')
        link_regx2 = re.compile('<li class="b_algo"><h2><a target="_blank" href="(.*?)"')
        try:
            links1 = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links1 + links2
            for link in links_list:
                link = re.sub('<(\/)?strong>|<span.*?>|<|>', '', link)
                if not (link.startswith('http') or link.startswith('https')):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain not in self.subdomains and subdomain != self.domain:
                    logger.info('{engine_name}: {subdomain}'.format(engine_name=self.engine_name, subdomain=subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list


class Yahoo(EngineBase):
    def __init__(self, domain, q, verbose):
        base_url = "https://search.yahoo.com/search?p=site%3A{domain}%20-domain%3Awww.{domain}&b={page_no}"
        super(Yahoo,self).__init__(base_url,domain,q,verbose)
        self.engine_name = "Yahoo"
        self.MAX_DOMAINS = 10
        self.MAX_PAGES = 0

    def extract_domains(self, resp):
        link_regx2 = re.compile('<span class=" fz-.*? fw-m fc-12th wr-bw.*?">(.*?)</span>')
        link_regx = re.compile('<span class="txt"><span class=" cite fw-xl fz-15px">(.*?)</span>')
        links_list = []
        try:
            links = link_regx.findall(resp)
            links2 = link_regx2.findall(resp)
            links_list = links + links2
            for link in links_list:
                link = re.sub("<(\/)?b>", "", link)
                if not link.startswith('http'):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if not subdomain.endswith(self.domain):
                    continue
                if subdomain and subdomain not in self.subdomains and subdomain != self.domain:
                    logger.info('{engine_name}: {subdomain}'.format(engine_name=self.engine_name, subdomain=subdomain))
                    self.subdomains.append(subdomain.strip())
        except Exception:
            pass

        return links_list

    def check_response_errors(self, resp):
        if isinstance(resp,int):
            logger.warning("Please use proxy to access Yahoo!")
            logger.warning("Finished now the Yahoo Enumeration ...")
            return False
        return True

    def send_req(self, page_no=1):
        url = self.base_url.format(domain=self.domain, page_no=page_no)
        try:
            #因为众所周知的原因，访问yahoo和Google需要使用代理，这里我使用了自己ss
            resp = self.session.get(url,proxies=proxies,headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None
        
        return self.get_response(resp)


class Baidu(EngineBase):
    def __init__(self,domain,q,verbose):
        base_url = "https://www.baidu.com/s?ie=UTF-8&wd=site%3A{domain}%20-site%3Awww.{domain}&pn={page_no}"
        super(Baidu,self).__init__(base_url,domain,q,verbose)
        self.MAX_PAGES = 30
        self.engine_name = 'Baidu'

    def extract_domains(self, resp):
        links = list()
        found_newdomain = False
        subdomain_list = []
        link_regx = re.compile('<a.*?class="c-showurl".*?>(.*?)</a>')
        try:
            links = link_regx.findall(resp)
            for link in links:
                link = re.sub('<.*?>|>|<|&nbsp;', '', link)
                if not (link.startswith('http') or link.startswith('https')):
                    link = "http://" + link
                subdomain = urlparse.urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        logger.info('{engine_name}: {subdomain}'.format(engine_name=self.engine_name, subdomain=subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.querydomain = self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)


class EnumSubDomain(object):
    def __init__(self, domain, response_filter=None, dns_servers=None, skip_rsc=False, debug=False, split=None, engines=[]):
        self.project_directory = os.path.abspath(os.path.dirname(__file__))
        logger.info('Version: {v}'.format(v=__version__))
        logger.info('----------')
        logger.info('Start domain: {d}'.format(d=domain))
        self.engines = engines
        self.data = {}
        self.domain = domain
        self.skip_rsc = skip_rsc
        self.split = split
        self.stable_dns_servers = ['1.1.1.1', '223.5.5.5']
        if dns_servers is None:
            dns_servers = [
                '223.5.5.5',  # AliDNS
                '114.114.114.114',  # 114DNS
                '1.1.1.1',  # Cloudflare
                '119.29.29.29',  # DNSPod
                '1.2.4.8',  # sDNS
                # '8.8.8.8', # Google DNS, 延时太高了
            ]

        random.shuffle(dns_servers)
        self.dns_servers = dns_servers
        self.resolver = None
        self.loop = asyncio.get_event_loop()
        self.general_dicts = []
        # Mark whether the current domain name is a pan-resolved domain name
        self.is_wildcard_domain = False
        # Use a nonexistent domain name to determine whether
        # there is a pan-resolve based on the DNS resolution result
        self.wildcard_sub = 'feei-esd-{random}'.format(random=random.randint(0, 9999))
        self.wildcard_sub3 = 'feei-esd-{random}.{random}'.format(random=random.randint(0, 9999))
        # There is no domain name DNS resolution IP
        self.wildcard_ips = []
        # No domain name response HTML
        self.wildcard_html = None
        self.wildcard_html_len = 0
        self.wildcard_html3 = None
        self.wildcard_html3_len = 0
        # Subdomains that are consistent with IPs that do not have domain names
        self.wildcard_subs = []
        # Wildcard domains use RSC
        self.wildcard_domains = {}
        # Corotines count
        self.coroutine_count = None
        self.coroutine_count_dns = 100000
        self.coroutine_count_request = 100
        # dnsaio resolve timeout
        self.resolve_timeout = 2
        # RSC ratio
        self.rsc_ratio = 0.8
        self.remainder = 0
        # Request Header
        self.request_headers = {
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Cache-Control': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Baiduspider',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'DNT': '1',
            'Referer': 'http://www.baidu.com/',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
        }
        # Filter the domain's response(regex)
        self.response_filter = response_filter
        # debug mode
        self.debug = debug
        if self.debug:
            logger.setLevel(logging.DEBUG)
        # collect redirecting domains and response domains
        self.domains_rs = []
        self.domains_rs_processed = []

    def generate_general_dicts(self, line):
        """
        Generate general subdomains dicts
        :param line:
        :return:
        """
        letter_count = line.count('{letter}')
        number_count = line.count('{number}')
        letters = itertools.product(string.ascii_lowercase, repeat=letter_count)
        letters = [''.join(l) for l in letters]
        numbers = itertools.product(string.digits, repeat=number_count)
        numbers = [''.join(n) for n in numbers]
        for l in letters:
            iter_line = line.replace('{letter}' * letter_count, l)
            self.general_dicts.append(iter_line)
        number_dicts = []
        for gd in self.general_dicts:
            for n in numbers:
                iter_line = gd.replace('{number}' * number_count, n)
                number_dicts.append(iter_line)
        if len(number_dicts) > 0:
            return number_dicts
        else:
            return self.general_dicts

    def load_sub_domain_dict(self):
        """
        Load subdomains from files and dicts
        :return:
        """
        dicts = []
        if self.debug:
            path = '{pd}/subs-test.esd'.format(pd=self.project_directory)
        else:
            path = '{pd}/subs.esd'.format(pd=self.project_directory)
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                # skip comments and space
                if '#' in line or line == '':
                    continue
                if '{letter}' in line or '{number}' in line:
                    self.general_dicts = []
                    dicts_general = self.generate_general_dicts(line)
                    dicts += dicts_general
                else:
                    # compatibility other dicts
                    line = line.strip('.')
                    dicts.append(line)
        dicts = list(set(dicts))
        # root domain
        dicts.append('@')
        # split dict
        if self.split is not None:
            s = self.split.split('/')
            dicts_choose = int(s[0])
            dicts_count = int(s[1])
            dicts_every = int(math.ceil(len(dicts)/dicts_count))
            dicts = [dicts[i:i+dicts_every] for i in range(0, len(dicts), dicts_every)][dicts_choose-1]
            logger.info('Sub domain dict split {count} and get {choose}st'.format(count=dicts_count, choose=dicts_choose))

        return dicts

    async def query(self, sub):
        """
        Query domain
        :param sub:
        :return:
        """
        ret = None
        # root domain
        if sub == '@' or sub == '':
            sub_domain = self.domain
        else:
            sub_domain = '{sub}.{domain}'.format(sub=sub, domain=self.domain)
        try:
            ret = await self.resolver.query(sub_domain, 'A')
            ret = [r.host for r in ret]
            domain_ips = [s for s in ret]
            # It is a wildcard domain name and
            # the subdomain IP that is burst is consistent with the IP
            # that does not exist in the domain name resolution,
            # the response similarity is discarded for further processing.
            if self.is_wildcard_domain and (sorted(self.wildcard_ips) == sorted(domain_ips) or set(domain_ips).issubset(self.wildcard_ips)):
                if self.skip_rsc:
                    logger.debug('{sub} maybe wildcard subdomain, but it is --skip-rsc mode now, it will be drop this subdomain in results'.format(sub=sub_domain))
                else:
                    logger.debug('{r} maybe wildcard domain, continue RSC {sub}'.format(r=self.remainder, sub=sub_domain, ips=domain_ips))
            else:
                if sub != self.wildcard_sub:
                    self.data[sub_domain] = sorted(domain_ips)
                    logger.info('{r} {sub} {ips}'.format(r=self.remainder, sub=sub_domain, ips=domain_ips))
        except aiodns.error.DNSError as e:
            err_code, err_msg = e.args[0], e.args[1]
            # 1:  DNS server returned answer with no data
            # 4:  Domain name not found
            # 11: Could not contact DNS servers
            # 12: Timeout while contacting DNS servers
            if err_code not in [1, 4, 11, 12]:
                logger.info('{domain} {exception}'.format(domain=sub_domain, exception=e))
        except Exception as e:
            logger.info(sub_domain)
            logger.warning(traceback.format_exc())
        self.remainder += -1
        return sub, ret

    @staticmethod
    def limited_concurrency_coroutines(coros, limit):
        futures = [
            asyncio.ensure_future(c)
            for c in islice(coros, 0, limit)
        ]

        async def first_to_finish():
            while True:
                await asyncio.sleep(0)
                for f in futures:
                    if f.done():
                        futures.remove(f)
                        try:
                            nf = next(coros)
                            futures.append(
                                asyncio.ensure_future(nf))
                        except StopIteration:
                            pass
                        return f.result()

        while len(futures) > 0:
            yield first_to_finish()

    async def start(self, tasks):
        """
        Limit the number of coroutines for reduce memory footprint
        :param tasks:
        :return:
        """
        for res in self.limited_concurrency_coroutines(tasks, self.coroutine_count):
            await res

    @staticmethod
    def data_clean(data):
        try:
            html = re.sub(r'\s', '', data)
            html = re.sub(r'<script(?!.*?src=).*?>.*?</script>', '', html)
            return html
        except:
            return data

    @staticmethod
    @backoff.on_exception(backoff.expo, TimeoutError, max_tries=3)
    async def fetch(session, url):
        """
        Fetch url response with session
        :param session:
        :param url:
        :return:
        """
        try:
            async with async_timeout.timeout(20):
                async with session.get(url) as response:
                    return await response.text(), response.history
        except Exception as e:
            # TODO 当在随机DNS场景中只做响应相似度比对的话，如果域名没有Web服务会导致相似度比对失败从而丢弃
            logger.warning('fetch exception: {e} {u}'.format(e=type(e).__name__, u=url))
            return None, None

    async def similarity(self, sub):
        """
        Enumerate subdomains by responding to similarities
        :param sub:
        :return:
        """
        # root domain
        if sub == '@' or sub == '':
            sub_domain = self.domain
        else:
            sub_domain = '{sub}.{domain}'.format(sub=sub, domain=self.domain)
        if sub_domain in self.domains_rs:
            self.domains_rs.remove(sub_domain)
        full_domain = 'http://{sub_domain}'.format(sub_domain=sub_domain)
        # 如果跳转中的域名是以下情况则不加入下一轮RSC
        skip_domain_with_history = [
            # 跳到主域名了
            '{domain}'.format(domain=self.domain),
            'www.{domain}'.format(domain=self.domain),
            # 跳到自己本身了，比如HTTP跳HTTPS
            '{domain}'.format(domain=sub_domain),
        ]
        try:
            regex_domain = r"((?!\/)(?:(?:[a-z\d-]*\.)+{d}))".format(d=self.domain)
            resolver = AsyncResolver(nameservers=self.dns_servers)
            conn = aiohttp.TCPConnector(resolver=resolver)
            async with aiohttp.ClientSession(connector=conn, headers=self.request_headers) as session:
                html, history = await self.fetch(session, full_domain)
                html = self.data_clean(html)
                if history is not None and len(history) > 0:
                    location = str(history[-1].headers['location'])
                    if '.' in location:
                        location_split = location.split('/')
                        if len(location_split) > 2:
                            location = location_split[2]
                        else:
                            location = location
                        try:
                            location = re.match(regex_domain, location).group(0)
                        except AttributeError:
                            location = location
                        status = history[-1].status
                        if location in skip_domain_with_history:
                            logger.debug('domain in skip: {s} {r} {l}'.format(s=sub_domain, r=status, l=location))
                            return
                        else:
                            # cnsuning.com suning.com
                            if location[-len(self.domain) - 1:] == '.{d}'.format(d=self.domain):
                                # collect redirecting's domains
                                if location not in self.domains_rs:
                                    if location not in self.domains_rs_processed:
                                        logger.info('[{sd}] add redirect domain: {l}({len})'.format(sd=sub_domain, l=location, len=len(self.domains_rs)))
                                        self.domains_rs.append(location)
                                        self.domains_rs_processed.append(location)
                            else:
                                logger.info('not same domain: {l}'.format(l=location))
                    else:
                        logger.info('not domain(maybe path): {l}'.format(l=location))
                if html is None:
                    logger.warning('domain\'s html is none: {s}'.format(s=sub_domain))
                    return
                # collect response html's domains
                response_domains = re.findall(regex_domain, html)
                response_domains = list(set(response_domains) - set([sub_domain]))
                for rd in response_domains:
                    rd = rd.strip().strip('.')
                    if rd.count('.') >= sub_domain.count('.') and rd[-len(sub_domain):] == sub_domain:
                        continue
                    if rd not in self.domains_rs:
                        if rd not in self.domains_rs_processed:
                            logger.info('[{sd}] add response domain: {s}({l})'.format(sd=sub_domain, s=rd, l=len(self.domains_rs)))
                            self.domains_rs.append(rd)
                            self.domains_rs_processed.append(rd)

                if len(html) == self.wildcard_html_len:
                    ratio = 1
                else:
                    # SPEED 4 2 1, but here is still the bottleneck
                    # real_quick_ratio() > quick_ratio() > ratio()
                    # TODO bottleneck
                    if sub.count('.') == 0:  # secondary sub, ex: www
                        ratio = SequenceMatcher(None, html, self.wildcard_html).real_quick_ratio()
                        ratio = round(ratio, 3)
                    else:  # tertiary sub, ex: home.dev
                        ratio = SequenceMatcher(None, html, self.wildcard_html3).real_quick_ratio()
                        ratio = round(ratio, 3)
                self.remainder += -1
                if ratio > self.rsc_ratio:
                    # passed
                    logger.debug('{r} RSC ratio: {ratio} (passed) {sub}'.format(r=self.remainder, sub=sub_domain, ratio=ratio))
                else:
                    # added
                    # for def distinct func
                    # self.wildcard_domains[sub_domain] = html
                    if self.response_filter is not None:
                        for resp_filter in self.response_filter.split(','):
                            if resp_filter in html:
                                logger.debug('{r} RSC filter in response (passed) {sub}'.format(r=self.remainder, sub=sub_domain))
                                return
                            else:
                                continue
                        self.data[sub_domain] = self.wildcard_ips
                    else:
                        self.data[sub_domain] = self.wildcard_ips
                    logger.info('{r} RSC ratio: {ratio} (added) {sub}'.format(r=self.remainder, sub=sub_domain, ratio=ratio))
        except Exception as e:
            logger.debug(traceback.format_exc())
            return

    def distinct(self):
        for domain, html in self.wildcard_domains.items():
            for domain2, html2 in self.wildcard_domains.items():
                ratio = SequenceMatcher(None, html, html2).real_quick_ratio()
                if ratio > self.rsc_ratio:
                    # remove this domain
                    if domain2 in self.data:
                        del self.data[domain2]
                    m = 'Remove'
                else:
                    m = 'Stay'
                logger.info('{d} : {d2} {ratio} {m}'.format(d=domain, d2=domain2, ratio=ratio, m=m))

    def dnspod(self):
        """
        http://feei.cn/esd
        :return:
        """
        try:
            content = requests.get('http://www.dnspod.cn/proxy_diagnose/recordscan/{domain}?callback=feei'.format(domain=self.domain), timeout=5).text
            domains = re.findall(r'[^": ]*{domain}'.format(domain=self.domain), content)
            domains = list(set(domains))
            tasks = (self.query(''.join(domain.rsplit(self.domain, 1)).rstrip('.')) for domain in domains)
            self.loop.run_until_complete(self.start(tasks))
        except Exception as e:
            domains = []
        return domains

    def run(self):
        """
        Run
        :return:
        """
        start_time = time.time()
        subs = self.load_sub_domain_dict()
        self.remainder = len(subs)
        logger.info('Sub domain dict count: {c}'.format(c=len(subs)))
        logger.info('Generate coroutines...')
        # Verify that all DNS server results are consistent
        stable_dns = []
        wildcard_ips = None
        last_dns = []
        only_similarity = False
        for dns in self.dns_servers:
            self.resolver = aiodns.DNSResolver(loop=self.loop, nameservers=[dns], timeout=self.resolve_timeout)
            job = self.query(self.wildcard_sub)
            sub, ret = self.loop.run_until_complete(job)
            logger.info('@{dns} {sub} {ips}'.format(dns=dns, sub=sub, ips=ret))
            if ret is None:
                ret = None
            else:
                ret = sorted(ret)

            if dns in self.stable_dns_servers:
                wildcard_ips = ret
            stable_dns.append(ret)

            if ret:
                equal = [False for r in ret if r not in last_dns]
                if len(last_dns) != 0 and False in equal:
                    only_similarity = self.is_wildcard_domain = True
                    logger.info('Is a random resolve subdomain.')
                    break
                else:
                    last_dns = ret

        is_all_stable_dns = stable_dns.count(stable_dns[0]) == len(stable_dns)
        if not is_all_stable_dns:
            logger.info('Is all stable dns: NO, use the default dns server')
            self.resolver = aiodns.DNSResolver(loop=self.loop, nameservers=self.stable_dns_servers, timeout=self.resolve_timeout)
        # Wildcard domain
        is_wildcard_domain = not (stable_dns.count(None) == len(stable_dns))
        if is_wildcard_domain or self.is_wildcard_domain:
            if not self.skip_rsc:
                logger.info('This is a wildcard domain, will enumeration subdomains use by DNS+RSC.')
            else:
                logger.info('This is a wildcard domain, but it is --skip-rsc mode now, it will be drop all random resolve subdomains in results')
            self.is_wildcard_domain = True
            if wildcard_ips is not None:
                self.wildcard_ips = wildcard_ips
            else:
                self.wildcard_ips = stable_dns[0]
            logger.info('Wildcard IPS: {ips}'.format(ips=self.wildcard_ips))
            if not self.skip_rsc:
                try:
                    self.wildcard_html = requests.get('http://{w_sub}.{domain}'.format(w_sub=self.wildcard_sub, domain=self.domain), headers=self.request_headers, timeout=10, verify=False).text
                    self.wildcard_html = self.data_clean(self.wildcard_html)
                    self.wildcard_html_len = len(self.wildcard_html)
                    self.wildcard_html3 = requests.get('http://{w_sub}.{domain}'.format(w_sub=self.wildcard_sub3, domain=self.domain), headers=self.request_headers, timeout=10, verify=False).text
                    self.wildcard_html3 = self.data_clean(self.wildcard_html3)
                    self.wildcard_html3_len = len(self.wildcard_html3)
                    logger.info('Wildcard domain response html length: {len} 3length: {len2}'.format(len=self.wildcard_html_len, len2=self.wildcard_html3_len))
                except requests.exceptions.SSLError:
                    logger.warning('SSL Certificate Error!')
                except requests.exceptions.ConnectTimeout:
                    logger.warning('Request response content failed, check network please!')
                except requests.exceptions.ReadTimeout:
                    self.wildcard_html = self.wildcard_html3 = ''
                    self.wildcard_html_len = self.wildcard_html3_len = 0
                    logger.warning('Request response content timeout, {w_sub}.{domain} and {w_sub3}.{domain} maybe not a http service, content will be set to blank!'.format(w_sub=self.wildcard_sub, domain=self.domain, w_sub3=self.wildcard_sub3))
        else:
            logger.info('Not a wildcard domain')

        if not only_similarity:
            self.coroutine_count = self.coroutine_count_dns
            tasks = (self.query(sub) for sub in subs)
            self.loop.run_until_complete(self.start(tasks))
        dns_time = time.time()
        time_consume_dns = int(dns_time - start_time)

        if self.is_wildcard_domain and not self.skip_rsc:
            # Response similarity comparison
            dns_subs = []
            for domain, ips in self.data.items():
                logger.info('{domain} {ips}'.format(domain=domain, ips=ips))
                dns_subs.append(domain.replace('.{0}'.format(self.domain), ''))
            self.wildcard_subs = list(set(subs) - set(dns_subs))
            logger.info('Enumerates {len} sub domains by DNS mode in {tcd}.'.format(len=len(self.data), tcd=str(datetime.timedelta(seconds=time_consume_dns))))
            logger.info('Will continue to test the distinct({len_subs}-{len_exist})={len_remain} domains used by RSC, the speed will be affected.'.format(len_subs=len(subs), len_exist=len(self.data), len_remain=len(self.wildcard_subs)))
            self.coroutine_count = self.coroutine_count_request
            self.remainder = len(self.wildcard_subs)
            tasks = (self.similarity(sub) for sub in self.wildcard_subs)
            self.loop.run_until_complete(self.start(tasks))

            # Distinct last domains use RSC
            # Maybe misinformation
            # self.distinct()

            time_consume_request = int(time.time() - dns_time)
            logger.info('Requests time consume {tcr}'.format(tcr=str(datetime.timedelta(seconds=time_consume_request))))
        # RS(redirect/response) domains
        while len(self.domains_rs) != 0:
            logger.info('RS(redirect/response) domains({l})...'.format(l=len(self.domains_rs)))
            tasks = (self.similarity(''.join(domain.rsplit(self.domain, 1)).rstrip('.')) for domain in self.domains_rs)
            self.loop.run_until_complete(self.start(tasks))

        # DNSPod JSONP API
        logger.info('Collect DNSPod JSONP API\'s subdomains...')
        domains = self.dnspod()
        logger.info('DNSPod JSONP API Count: {c}'.format(c=len(domains)))

        # CA subdomain info
        logger.info('Collect subdomains in CA...')
        ca_subdomains = CAInfo(self.domain).get_subdomains()
        tasks = (self.query(sub) for sub in ca_subdomains)
        self.loop.run_until_complete(self.start(tasks))
        logger.info('CA subdomain count: {c}'.format(c=len(ca_subdomains)))

        # DNS Transfer Vulnerability
        logger.info('Check DNS Transfer Vulnerability in {domain}'.format(domain=self.domain))
        transfer_info = DNSTransfer(self.domain).transfer_info()
        if len(transfer_info):
            logger.warning('DNS Transfer Vulnerability found in {domain}!'.format(domain=self.domain))
            tasks = (self.query(sub) for sub in transfer_info)
            self.loop.run_until_complete(self.start(tasks))
        logger.info('DNS Transfer subdomain count: {c}'.format(c=len(transfer_info)))

        # Use search engines to enumerate subdomains (support Baidu,Bing,Google,Yahoo)
        logger.info('Enumerating subdomains with Baidu,Bing,Google and Yahoo')
        subdomains_queue = multiprocessing.Manager().list()
        enums = [enum(self.domain,q=subdomains_queue,verbose=False) for enum in self.engines]
        for enum in enums:
            enum.start()
        for enum in enums:
            enum.join()
        subdomains = set(subdomains_queue)
        if len(subdomains):
            tasks = (self.query(sub[:sub.find('.')]) for sub in subdomains)
            self.loop.run_until_complete(self.start(tasks))
        logger.info('Search engines subdomain count: {subdomains_count}'.format(subdomains_count=len(subdomains)))

        # write output
        tmp_dir = '/tmp/esd'
        if not os.path.isdir(tmp_dir):
            os.mkdir(tmp_dir, 0o777)
        output_path_with_time = '{td}/.{domain}_{time}.esd'.format(td=tmp_dir, domain=self.domain, time=datetime.datetime.now().strftime("%Y-%m_%d_%H-%M"))
        output_path = '{td}/.{domain}.esd'.format(td=tmp_dir, domain=self.domain)
        if len(self.data):
            max_domain_len = max(map(len, self.data)) + 2
        else:
            max_domain_len = 2
        output_format = '%-{0}s%-s\n'.format(max_domain_len)
        with open(output_path_with_time, 'w') as opt, open(output_path, 'w') as op:
            for domain, ips in self.data.items():

                # The format is consistent with other scanners to ensure that they are
                # invoked at the same time without increasing the cost of resolution
                if ips is None or len(ips) == 0:
                    ips_split = ''
                else:
                    ips_split = ','.join(ips)
                con = output_format % (domain, ips_split)
                op.write(con)
                opt.write(con)
        logger.info('Output: {op}'.format(op=output_path))
        logger.info('Output with time: {op}'.format(op=output_path_with_time))
        logger.info('Total domain: {td}'.format(td=len(self.data)))
        time_consume = int(time.time() - start_time)
        logger.info('Time consume: {tc}'.format(tc=str(datetime.timedelta(seconds=time_consume))))
        return self.data


def main():
    try:
        if len(sys.argv) < 2:
            logger.info("Usage: python ESD.py feei.cn [response filter] [--skip-rsc] [--split=1/4]")
            exit(0)
        domains = []
        param = sys.argv[1].strip()
        skip_rsc = False
        engines = [Baidu,Google,Bing,Yahoo]
        response_filter = None
        split = None
        if len(sys.argv) >= 3:
            if sys.argv[2].strip().startswith('--skip-rsc'):
                skip_rsc = True
            elif sys.argv[2].strip().startswith('--split'):
                split = sys.argv[2].strip()
            else:
                response_filter = sys.argv[2].strip()
            for i in range(3, len(sys.argv)):
                if sys.argv[i].strip().startswith('--skip-rsc'):
                    skip_rsc = True
                if sys.argv[i].strip().startswith('--split'):
                    split = sys.argv[i].strip()
        else:
            response_filter = None
        if 'esd' in os.environ:
            debug = os.environ['esd']
        else:
            debug = False

        if split is not None:
            s = split.split('=')
            split = s[1]

        logger.info('Debug: {d}'.format(d=debug))
        logger.info('--skip-rsc: {rsc}'.format(rsc=skip_rsc))
        logger.info('--split: {s}'.format(s=split))
        if os.path.isfile(param):
            with open(param) as fh:
                for line_domain in fh:
                    line_domain = line_domain.strip().lower()
                    re_domain = re.findall(r'^(([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,})$', line_domain)
                    if len(re_domain) > 0 and re_domain[0][0] == line_domain:
                        domains.append(line_domain)
                    else:
                        logger.error('Domain validation failed: {d}'.format(d=line_domain))
        else:
            if ',' in param:
                for p in param.split(','):
                    domains.append(p.strip())
            else:
                domains.append(param)
        logger.info('Total target domains: {ttd}'.format(ttd=len(domains)))
        for d in domains:
            esd = EnumSubDomain(d, response_filter, skip_rsc=skip_rsc, debug=debug, split=split, engines=engines)
            esd.run()
    except KeyboardInterrupt:
        logger.info('Bye :)')
        exit(0)

if __name__ == '__main__':
    main()
