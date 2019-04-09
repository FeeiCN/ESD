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
import tldextract
import json
import configparser
import base64
from tqdm import *
from colorama import Fore
from shodan import Shodan
import censys.certificates
from shodan.cli.helpers import get_api_key
from optparse import OptionParser
import urllib.parse as urlparse
from collections import Counter
from aiohttp.resolver import AsyncResolver
from itertools import islice
from difflib import SequenceMatcher

__version__ = '0.0.24'

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

ssl.match_hostname = lambda cert, hostname: True


# 只采用了递归，速度非常慢，在优化完成前不建议开启
# TODO:优化DNS查询，递归太慢了
class DNSQuery(object):
    def __init__(self, root_domain, subs, suffix):
        # root domain
        self.suffix = suffix
        self.sub_domains = []
        if root_domain:
            self.sub_domains.append(root_domain)

        for sub in subs:
            sub = ''.join(sub.rsplit(suffix, 1)).rstrip('.')
            self.sub_domains.append('{sub}.{domain}'.format(sub=sub, domain=suffix))

    def dns_query(self):
        """
        soa,txt,mx,aaaa
        :param sub:
        :return:
        """
        final_list = []
        for subdomain in self.sub_domains:
            try:
                soa = []
                q_soa = dns.resolver.query(subdomain, 'SOA')
                for a in q_soa:
                    soa.append(str(a.rname).strip('.'))
                    soa.append(str(a.mname).strip('.'))
            except Exception as e:
                logger.warning('Query failed. {e}'.format(e=str(e)))
            try:
                aaaa = []
                q_aaaa = dns.resolver.query(subdomain, 'AAAA')
                aaaa = [str(a.address).strip('.') for a in q_aaaa]
            except Exception as e:
                logger.warning('Query failed. {e}'.format(e=str(e)))
            try:
                txt = []
                q_txt = dns.resolver.query(subdomain, 'TXT')
                txt = [t.strings[0].decode('utf-8').strip('.') for t in q_txt]
            except Exception as e:
                logger.warning('Query failed. {e}'.format(e=str(e)))
            try:
                mx = []
                q_mx = dns.resolver.query(subdomain, 'MX')
                mx = [str(m.exchange).strip('.') for m in q_mx]
            except Exception as e:
                logger.warning('Query failed. {e}'.format(e=str(e)))
            domain_set = soa + aaaa + txt + mx
            domain_list = [i for i in domain_set]
            for p in domain_set:
                re_domain = re.findall(r'^(([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\.?)$', p)
                if len(re_domain) > 0 and subdomain in re_domain[0][0] and tldextract.extract(p).suffix != '':
                    continue
                else:
                    domain_list.remove(p)
            final_list = domain_list + final_list
        # 递归调用，在子域名的dns记录中查找新的子域名
        recursive = []
        # print("before: {0}".format(final_list))
        # print("self.sub_domain: {0}".format(self.sub_domains))
        final_list = list(set(final_list).difference(set(self.sub_domains)))
        # print("after: {0}".format(final_list))
        if final_list:
            d = DNSQuery('', final_list, self.suffix)
            recursive = d.dns_query()
        return final_list + recursive


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
        except BaseException:
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


# 使用shodan接口进行枚举，但经测试并不能增加多少成果
class ShodanEngine(object):
    def __init__(self, skey, conf, domain):
        self.domain = domain
        self.conf = conf
        self.skey = skey
        self.api = None

    # 初始化shodan的api
    def initialize(self, base_dir):
        if self.skey:
            logger.info('Initializing the shodan api.')
            result = os.system('shodan init {skey}'.format(skey=self.skey))
            if result:
                logger.warning('Initializ failed, please check your key.')
                return False
            self.conf.set("shodan", "shodan_key", self.skey)
            self.conf.write(open(base_dir + "/key.ini", "w"))
            self.api = Shodan(get_api_key())
        else:
            from click.exceptions import ClickException
            try:
                key = None if get_api_key() == '' else get_api_key()
                if key:
                    self.api = Shodan(key)
                else:
                    return False
            except ClickException as e:
                logger.warning('The shodan api is empty so you can not use shodan api.')
                return False
        return True

    def search(self):
        subs = list()
        result = self.api.search('hostname:{domain}'.format(domain=self.domain))
        for service in result['matches']:
            domain = service['hostnames'][0]
            subs.append(domain.rsplit(self.domain, 1)[0].strip('.'))
        return set(subs)


# fofa的sdk不支持python3，就只能调用restful api了，但是挖掘成果比shodan多
class FofaEngine(object):
    def __init__(self, fofa_struct, conf, domain):
        self.base_url = "https://fofa.so/api/v1/search/all?email={email}&key={key}&qbase64={domain}"
        self.email = fofa_struct['femail']
        self.fkey = fofa_struct['fkey']
        self.domain = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.timeout = 30
        self.conf = conf

    def initialize(self, base_dir):
        if self.fkey is not None and self.email is not None:
            self.conf.set("fofa", "fofa_key", self.fkey)
            self.conf.set("fofa", "fofa_email", self.email)
            self.conf.write(open(base_dir + "/key.ini", "w"))
            return True
        else:
            self.fkey = self.conf.items("fofa")[0][1]
            self.email = self.conf.items("fofa")[1][1]
            if self.fkey and self.email:
                return True
        return False

    def search(self):
        result = list()
        url = self.base_url.format(email=self.email, key=self.fkey, domain=self.domain)
        try:
            resp = requests.Session().get(url, headers=self.headers, timeout=self.timeout)
            json_resp = json.loads(resp.text)
            for res in json_resp['results']:
                domain = urlparse.urlparse(res[0]).netloc
                result.append(domain.rsplit(self.domain, 1)[0].strip('.'))
        except Exception as e:
            result = []

        return result


# Zoomeye的效果还可以，但是比fofa还贵
class ZoomeyeEngine(object):
    def __init__(self, domain, zoomeye_struct, conf):
        self.headers = {
            "Authorization": "JWT {token}"
        }
        self.url = 'https://api.zoomeye.org/web/search?query=site:{domain}&page={num}'
        self.domain = domain
        self.zoomeye_struct = zoomeye_struct
        self.conf = conf

    def initialize(self, base_dir):
        username = self.zoomeye_struct['username']
        password = self.zoomeye_struct['password']
        if username != '' and password != '':
            resp = requests.Session().post(url='https://api.zoomeye.org/user/login', data=json.dumps(self.zoomeye_struct))
            resp_json = json.loads(resp.text)
        else:
            username = self.conf.items("zoomeye")[0][1]
            password = self.conf.items("zoomeye")[1][1]
            if username != '' and password != '':
                self.zoomeye_struct['username'] = username
                self.zoomeye_struct['password'] = password
                resp = requests.Session().post(url='https://api.zoomeye.org/user/login', data=json.dumps(self.zoomeye_struct))
                resp_json = json.loads(resp.text)
            else:
                return False
        if 'error' in resp_json.keys():
            # logger.warning('In Zoomeye' + resp_json['message'])
            return False
        self.conf.set("zoomeye", "zoomeye_username", username)
        self.conf.set("zoomeye", "zoomeye_password", password)
        self.conf.write(open(base_dir + "/key.ini", "w"))
        self.headers['Authorization'] = "JWT {token}".format(token=resp_json['access_token'])

        return True

    def search(self, num):
        url = self.url.format(domain=self.domain, num=num)
        resp = requests.Session().get(url=url, headers=self.headers)

        try:
            # zoomeye对于频繁的api调用会做限制，但是降低频率又会影响效率
            response = json.loads(resp.text)
        except Exception:
            response = None

        return response

    def enumerate(self):
        flag = True
        num = 1
        result = list()
        while flag:
            response = self.search(num)
            if response is None or 'error' in response.keys():
                # print(response)
                flag = False
            else:
                match_list = response["matches"]
                for block in match_list:
                    domain = block['site']
                    result.append(domain.rsplit(self.domain, 1)[0].strip('.'))
                num = num + 1
        return result


# censys的接口有点不稳定，经常出现timeout的情况
class CensysEngine(object):
    def __init__(self, domain, censys_struct, conf):
        self.domain = domain
        self.conf = conf
        self.censys_struct = censys_struct
        self.certificates = None
        self.fields = ['parsed.subject_dn']

    def initialize(self, base_dir):
        uid = self.censys_struct['uid']
        secret = self.censys_struct['secret']
        try:
            if uid is not None and secret is not None:
                self.certificates = censys.certificates.CensysCertificates(uid, secret)
            else:
                uid = self.conf.items("censys")[0][1]
                secret = self.conf.items("censys")[1][1]
                if uid != '' and secret != '':
                    self.certificates = censys.certificates.CensysCertificates(uid, secret)
                else:
                    return False

            self.conf.set("censys", "UID", uid)
            self.conf.set("censys", "SECRET", secret)
            self.conf.write(open(base_dir + "/key.ini", "w"))
        except Exception as e:
            return False

        return True

    def search(self):
        result = list()
        try:
            for c in self.certificates.search(self.domain, fields=self.fields):
                subject = c['parsed.subject_dn'].strip()
                reg_domain = self.domain.replace('.', '[.]')
                reg_text = r'(([-a-zA-Z0-9]+[.])*{reg_domain}$)'.format(reg_domain=reg_domain)
                match_list = re.findall(reg_text, subject)
                if match_list:
                    domain = match_list[0][0]
                    result.append(domain.rsplit(self.domain, 1)[0].strip('.'))
        except Exception as e:
            logger.warning(str(e))
            return result
        else:
            return result


class EngineBase(multiprocessing.Process):
    def __init__(self, base_url, domain, q, verbose, proxy):
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
        self.proxy = proxy

    def get_page(self, num):
        return num + 10

    # 应当在子类里重写
    def check_response_errors(self, resp):
        return True

    def should_sleep(self):
        time.sleep(random.randint(2, 5))
        return

    def get_response(self, response):
        if response is None:
            return 0
        return response.text if hasattr(response, "text") else response.content

    def check_max_pages(self, num):
        if self.MAX_PAGES == 0:
            return False
        return num >= self.MAX_PAGES

    def send_req(self, page_no=1):
        url = self.base_url.format(domain=self.domain, page_no=page_no)
        try:
            resp = self.session.get(
                url, headers=self.headers, timeout=self.timeout)
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
            self.q.append(domain.rsplit(self.domain, 1)[0].strip('.'))


class Google(EngineBase):
    def __init__(self, domain, q, verbose, proxy):
        base_url = "https://www.google.com/search?q=site:{domain}+-www.{domain}&start={page_no}"
        super(Google, self).__init__(base_url, domain, q, verbose, proxy)
        self.MAX_DOMAINS = 11
        self.MAX_PAGES = 200
        self.engine_name = 'Google'

    def extract_domains(self, resp):
        links_list = list()
        link_regx = re.compile(r'<cite.*?>(.*?)<\/cite>')
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
        if isinstance(resp, int):
            logger.warning("Please use proxy to access Google!")
            logger.warning("Finished now the Google Enumeration ...")
            return False
        return True

    def send_req(self, page_no=1):
        url = self.base_url.format(domain=self.domain, page_no=page_no)
        try:
            resp = self.session.get(url, proxies=self.proxy, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None

        return self.get_response(resp)


class Bing(EngineBase):
    def __init__(self, domain, q, verbose, proxy):
        base_url = 'https://www.bing.com/search?q=domain%3A{domain}%20-www.{domain}&go=Submit&first={page_no}'
        super(Bing, self).__init__(base_url, domain, q, verbose, proxy)
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
                link = re.sub(r'<(\/)?strong>|<span.*?>|<|>', '', link)
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
    def __init__(self, domain, q, verbose, proxy):
        base_url = "https://search.yahoo.com/search?p=site%3A{domain}%20-domain%3Awww.{domain}&b={page_no}"
        super(Yahoo, self).__init__(base_url, domain, q, verbose, proxy)
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
                link = re.sub(r"<(\/)?b>", "", link)
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
        if isinstance(resp, int):
            logger.warning("Please use proxy to access Yahoo!")
            logger.warning("Finished now the Yahoo Enumeration ...")
            return False
        return True

    def send_req(self, page_no=1):
        url = self.base_url.format(domain=self.domain, page_no=page_no)
        try:
            resp = self.session.get(url, proxies=self.proxy, headers=self.headers, timeout=self.timeout)
        except Exception as e:
            resp = None

        return self.get_response(resp)


class Baidu(EngineBase):
    def __init__(self, domain, q, verbose, proxy):
        base_url = "https://www.baidu.com/s?ie=UTF-8&wd=site%3A{domain}%20-site%3Awww.{domain}&pn={page_no}"
        super(Baidu, self).__init__(base_url, domain, q, verbose, proxy)
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
    def __init__(self, domain, response_filter=None, dns_servers=None, skip_rsc=False, debug=False,
                 split=None, engines=[Baidu, Google, Bing, Yahoo], proxy={}, multiresolve=False,
                 shodan_key=None, fofa={'fkey': None, 'femail': None}, zoomeye={'username': None, 'password': None}, censys={'uid': None, 'secret': None}):
        self.project_directory = os.path.abspath(os.path.dirname(__file__))
        logger.info('Version: {v}'.format(v=__version__))
        logger.info('----------')
        logger.info('Start domain: {d}'.format(d=domain))
        self.engines = engines
        self.proxy = proxy
        self.data = {}
        self.domain = domain
        self.skip_rsc = skip_rsc
        self.split = split
        self.multiresolve = multiresolve
        self.skey = shodan_key
        self.fofa_struct = fofa
        self.conf = configparser.ConfigParser()
        self.zoomeye_struct = zoomeye
        self.censys_struct = censys
        self.stable_dns_servers = ['1.1.1.1', '223.5.5.5']
        if dns_servers is None:
            dns_servers = [
                '223.5.5.5',  # AliDNS
                '114.114.114.114',  # 114DNS
                '1.1.1.1',  # Cloudflare
                '119.29.29.29',  # DNSPod
                '1.2.4.8',  # sDNS
                # '11.1.1.1'  # test DNS, not available
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
        self.count = 0
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
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'}
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

        # split dict
        if self.split is not None:
            s = self.split.split('/')
            dicts_choose = int(s[0])
            dicts_count = int(s[1])
            dicts_every = int(math.ceil(len(dicts) / dicts_count))
            dicts = [dicts[i:i + dicts_every] for i in range(0, len(dicts), dicts_every)][dicts_choose - 1]
            logger.info('Sub domain dict split {count} and get {choose}st'.format(count=dicts_count, choose=dicts_choose))

        # root domain
        dicts.append('@')

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
            sub = ''.join(sub.rsplit(self.domain, 1)).rstrip('.')
            sub_domain = '{sub}.{domain}'.format(sub=sub, domain=self.domain)
        try:
            ret = await self.resolver.query(sub_domain, 'A')
        except aiodns.error.DNSError as e:
            err_code, err_msg = e.args[0], e.args[1]
            # 1:  DNS server returned answer with no data
            # 4:  Domain name not found
            # 11: Could not contact DNS servers
            # 12: Timeout while contacting DNS servers
            if err_code not in [1, 4, 11, 12]:
                logger.warning('{domain} {exception}'.format(domain=sub_domain, exception=e))
        except Exception as e:
            logger.info(sub_domain)
            logger.warning(traceback.format_exc())

        else:
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
                    print('', end='\n')
                    self.count += 1
                    logger.info('{r} {sub} {ips}'.format(r=self.remainder, sub=sub_domain, ips=domain_ips))
        self.remainder += -1
        return sub_domain, ret

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
                            futures.append(asyncio.ensure_future(nf))
                        except StopIteration:
                            pass
                        return f.result()

        while len(futures) > 0:
            yield first_to_finish()

    async def start(self, tasks, tasks_num):
        """
        Limit the number of coroutines for reduce memory footprint
        :param tasks:
        :return:
        """
        for res in tqdm(self.limited_concurrency_coroutines(tasks, self.coroutine_count), bar_format="%s{l_bar}%s{bar}%s{r_bar}%s" % (Fore.YELLOW, Fore.YELLOW, Fore.YELLOW, Fore.RESET), total=tasks_num):
            await res

    @staticmethod
    def data_clean(data):
        try:
            html = re.sub(r'\s', '', data)
            html = re.sub(r'<script(?!.*?src=).*?>.*?</script>', '', html)
            return html
        except BaseException:
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
            sub = ''.join(sub.rsplit(self.domain, 1)).rstrip('.')
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
                        if location in skip_domain_with_history and len(history) >= 2:
                            logger.debug('domain in skip: {s} {r} {l}'.format(s=sub_domain, r=status, l=location))
                            return
                        else:
                            # cnsuning.com suning.com
                            if location[-len(self.domain) - 1:] == '.{d}'.format(d=self.domain):
                                # collect redirecting's domains
                                if sub_domain != location and location not in self.domains_rs and location not in self.domains_rs_processed:
                                    print('', end='\n')
                                    logger.info('[{sd}] add redirect domain: {l}({len})'.format(sd=sub_domain, l=location, len=len(self.domains_rs)))
                                    self.domains_rs.append(location)
                                    self.domains_rs_processed.append(location)
                            else:
                                print('', end='\n')
                                logger.info('not same domain: {l}'.format(l=location))
                    else:
                        print('', end='\n')
                        logger.info('not domain(maybe path): {l}'.format(l=location))
                if html is None:
                    print('', end='\n')
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
                            print('', end='\n')
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
                    print('', end='\n')
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
        # noinspection PyBroadException
        try:
            content = requests.get('http://www.dnspod.cn/proxy_diagnose/recordscan/{domain}?callback=feei'.format(domain=self.domain), timeout=5).text
            domains = re.findall(r'[^": ]*{domain}'.format(domain=self.domain), content)
            domains = list(set(domains))
            tasks = (self.query(''.join(domain.rsplit(self.domain, 1)).rstrip('.')) for domain in domains)
            self.loop.run_until_complete(self.start(tasks, len(domains)))
        except Exception as e:
            domains = []
        return domains

    def check(self, dns):
        logger.info("Checking if DNS server {dns} is available".format(dns=dns))
        msg = b'\x5c\x6d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x05baidu\x03com\x00\x00\x01\x00\x01'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        repeat = {
            1: 'first',
            2: 'second',
            3: 'third'
        }
        for i in range(3):
            logger.info("Sending message to DNS server a {times} time".format(times=repeat[i + 1]))
            sock.sendto(msg, (dns, 53))
            try:
                sock.recv(4096)
                break
            except socket.timeout as e:
                logger.warning('Failed!')
            if i == 2:
                return False
        return True

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
            delay = self.check(dns)
            if not delay:
                logger.warning("@{dns} is not available, skip this DNS server".format(dns=dns))
                continue
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
                    logger.warning('Request response content timeout, {w_sub}.{domain} and {w_sub3}.{domain} maybe not a http service, content will be set to blank!'.format(w_sub=self.wildcard_sub,
                                                                                                                                                                             domain=self.domain,
                                                                                                                                                                             w_sub3=self.wildcard_sub3))
                except requests.exceptions.ConnectionError:
                    logger.error('ESD can\'t get the response text so the rsc will be skipped. ')
                    self.skip_rsc = True
        else:
            logger.info('Not a wildcard domain')

        if not only_similarity:
            self.coroutine_count = self.coroutine_count_dns
            tasks = (self.query(sub) for sub in subs)
            self.loop.run_until_complete(self.start(tasks, len(subs)))
            logger.info("Brute Force subdomain count: {total}".format(total=self.count))
        dns_time = time.time()
        time_consume_dns = int(dns_time - start_time)

        # DNSPod JSONP API
        logger.info('Collect DNSPod JSONP API\'s subdomains...')
        dnspod_domains = self.dnspod()
        logger.info('DNSPod JSONP API Count: {c}'.format(c=len(dnspod_domains)))

        # CA subdomain info
        ca_subdomains = []
        logger.info('Collect subdomains in CA...')
        ca_subdomains = CAInfo(self.domain).get_subdomains()
        if len(ca_subdomains):
            tasks = (self.query(sub) for sub in ca_subdomains)
            self.loop.run_until_complete(self.start(tasks, len(ca_subdomains)))
        logger.info('CA subdomain count: {c}'.format(c=len(ca_subdomains)))

        # DNS Transfer Vulnerability
        transfer_info = []
        logger.info('Check DNS Transfer Vulnerability in {domain}'.format(domain=self.domain))
        transfer_info = DNSTransfer(self.domain).transfer_info()
        if len(transfer_info):
            logger.warning('DNS Transfer Vulnerability found in {domain}!'.format(domain=self.domain))
            tasks = (self.query(sub) for sub in transfer_info)
            self.loop.run_until_complete(self.start(tasks, len(transfer_info)))
        logger.info('DNS Transfer subdomain count: {c}'.format(c=len(transfer_info)))

        # Use search engines to enumerate subdomains (support Baidu,Bing,Google,Yahoo)
        subdomains = []
        if self.engines:
            logger.info('Enumerating subdomains with search engine')
            subdomains_queue = multiprocessing.Manager().list()
            enums = [enum(self.domain, q=subdomains_queue, verbose=False, proxy=self.proxy) for enum in self.engines]
            for enum in enums:
                enum.start()
            for enum in enums:
                enum.join()
            subdomains = set(subdomains_queue)
            if len(subdomains):
                tasks = (self.query(sub) for sub in subdomains)
                self.loop.run_until_complete(self.start(tasks, len(subdomains)))
            logger.info('Search engines subdomain count: {subdomains_count}'.format(subdomains_count=len(subdomains)))

        # Use shodan to enumerate subdomains (need key and money)
        shodan_result = []
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.conf.read(base_dir + "/key.ini")
        shodan = ShodanEngine(self.skey, self.conf, self.domain)
        is_success = shodan.initialize(base_dir)
        if is_success:
            logger.info('Enumerating subdomains with Shodan')
            shodan_result = shodan.search()
            if len(shodan_result):
                tasks = (self.query(sub) for sub in shodan_result)
                self.loop.run_until_complete(self.start(tasks, len(shodan_result)))
            logger.info("Shodan subdomain count: {subdomains_count}".format(subdomains_count=len(shodan_result)))

        # Use fofa to enumerate subdomains (need key and money)
        fofa_result = []
        fofa = FofaEngine(self.fofa_struct, self.conf, self.domain)
        is_success = fofa.initialize(base_dir)
        if is_success:
            logger.info("Enumerating subdomains with Fofa")
            fofa_result = fofa.search()
            if len(fofa_result):
                tasks = (self.query(sub) for sub in fofa_result)
                self.loop.run_until_complete(self.start(tasks, len(fofa_result)))
            logger.info("Fofa subdomain count: {subdomains_count}".format(subdomains_count=len(fofa_result)))

        # Use zoomeye to enumerate subdomains (need account or money)
        zoomeye_result = []
        zoomeye = ZoomeyeEngine(self.domain, self.zoomeye_struct, self.conf)
        is_success = zoomeye.initialize(base_dir)
        if is_success:
            logger.info("Enumerating subdomains with Zoomeye")
            zoomeye_result = zoomeye.enumerate()
            if len(zoomeye_result):
                tasks = (self.query(sub) for sub in zoomeye_result)
                self.loop.run_until_complete(self.start(tasks, len(zoomeye_result)))
            logger.info("Zoomeye subdomain count: {subdomains_count}".format(subdomains_count=len(zoomeye_result)))

        censys_result = []
        censys = CensysEngine(self.domain, self.censys_struct, self.conf)
        is_success = censys.initialize(base_dir)
        if is_success:
            logger.info("Enumerating subdomains with Censys")
            censys_result = censys.search()
            if len(censys_result):
                tasks = (self.query(sub) for sub in censys_result)
                self.loop.run_until_complete(self.start(tasks, len(censys_result)))
            logger.info("Censys subdomain count: {subdomains_count}".format(subdomains_count=len(censys_result)))

        total_subs = set(subs + dnspod_domains + list(subdomains) + transfer_info + ca_subdomains + list(shodan_result) + fofa_result + zoomeye_result + censys_result)

        # Use TXT,SOA,MX,AAAA record to find sub domains
        if self.multiresolve:
            logger.info('Enumerating subdomains with TXT, SOA, MX, AAAA record...')
            dnsquery = DNSQuery(self.domain, total_subs, self.domain)
            record_info = dnsquery.dns_query()
            tasks = (self.query(record[:record.find('.')]) for record in record_info)
            self.loop.run_until_complete(self.start(tasks, len(record_info)))
            logger.info('DNS record subdomain count: {c}'.format(c=len(record_info)))

        if self.is_wildcard_domain and not self.skip_rsc:
            # Response similarity comparison
            total_subs = set(subs + dnspod_domains + list(subdomains) + transfer_info + ca_subdomains)
            self.wildcard_subs = list(set(subs).union(total_subs))
            logger.info('Enumerates {len} sub domains by DNS mode in {tcd}.'.format(len=len(self.data), tcd=str(datetime.timedelta(seconds=time_consume_dns))))
            logger.info('Will continue to test the distinct({len_subs}-{len_exist})={len_remain} domains used by RSC, the speed will be affected.'.format(len_subs=len(subs), len_exist=len(self.data),
                                                                                                                                                          len_remain=len(self.wildcard_subs)))
            self.coroutine_count = self.coroutine_count_request
            self.remainder = len(self.wildcard_subs)
            tasks = (self.similarity(sub) for sub in self.wildcard_subs)
            self.loop.run_until_complete(self.start(tasks, len(self.wildcard_subs)))

            # Distinct last domains use RSC
            # Maybe misinformation
            # self.distinct()

            time_consume_request = int(time.time() - dns_time)
            logger.info('Requests time consume {tcr}'.format(tcr=str(datetime.timedelta(seconds=time_consume_request))))
        # RS(redirect/response) domains
        while len(self.domains_rs) != 0:
            logger.info('RS(redirect/response) domains({l})...'.format(l=len(self.domains_rs)))
            tasks = (self.similarity(''.join(domain.rsplit(self.domain, 1)).rstrip('.')) for domain in self.domains_rs)

            self.loop.run_until_complete(self.start(tasks, len(self.domains_rs)))

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
                # invoked at the same time without increasing the cost of
                # resolution
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


def banner():
    print("""\033[94m
                 ______    _____   _____  
                |  ____|  / ____| |  __ \ 
                | |__    | (___   | |  | |
                |  __|    \___ \  | |  | |
                | |____   ____) | | |__| |
                |______| |_____/  |_____/\033[0m\033[93m
            # Enumeration sub domains @version: %s\033[92m
    """ % __version__)


def main():
    banner()
    parser = OptionParser('Usage: python ESD.py -d feei.cn -F response_filter -e baidu,google,bing,yahoo -p user:pass@host:port')
    parser.add_option('-d', '--domain', dest='domains', help='The domains that you want to enumerate')
    parser.add_option('-f', '--file', dest='input', help='Import domains from this file')
    parser.add_option('-F', '--filter', dest='filter', help='Response filter')
    parser.add_option('-s', '--skip-rsc', dest='skiprsc', help='Skip response similary compare', action='store_true', default=False)
    parser.add_option('-e', '--engines', dest='engines', help='Choose an engine in baidu,google,bing or yahoo, split with ","')
    parser.add_option('-S', '--split', dest='split', help='Split the dict into several parts', default='1/1')
    parser.add_option('-p', '--proxy', dest='proxy', help='Use socks5 proxy to access Google and Yahoo')
    parser.add_option('-m', '--multi-resolve', dest='multiresolve', help='Use TXT, AAAA, MX, SOA record to find subdomains', action='store_true', default=False)
    parser.add_option('--skey', '--shodan-key', dest='shodankey', help='Define the api of shodan')
    parser.add_option('--fkey', '--fofa-key', dest='fofakey', help='Define the key of fofa')
    parser.add_option('--femail', '--fofa-email', dest='fofaemail', help='The email of your fofa account')
    parser.add_option('--zusername', '--zoomeye-username', dest='zoomeyeusername', help='The username of your zoomeye account')
    parser.add_option('--zpassword', '--zoomeye-password', dest='zoomeyepassword', help='The password of your zoomeye account')
    parser.add_option('--cuid', '--censys-uid', dest='censysuid', help="The uid of your censys account")
    parser.add_option('--csecret', '--censys-secret', dest='censyssecret', help='The secret of your censys account')
    (options, args) = parser.parse_args()

    support_engines = {
        'baidu': Baidu,
        'google': Google,
        'bing': Bing,
        'yahoo': Yahoo,
    }

    domains = []
    engines = []
    response_filter = options.filter
    skip_rsc = options.skiprsc
    split_list = options.split.split('/')
    split = options.split
    multiresolve = options.multiresolve
    skey = options.shodankey

    fofa_struct = {
        'fkey': options.fofakey,
        'femail': options.fofaemail,
    }

    zoomeye_struct = {
        'username': options.zoomeyeusername,
        'password': options.zoomeyepassword,
    }

    censys_struct = {
        'uid': options.censysuid,
        'secret': options.censyssecret,
    }

    try:
        if len(split_list) != 2 or int(split_list[0]) > int(split_list[1]):
            logger.error('Invaild split parameter,can not split the dict')
            split = None
    except:
        logger.error('Split validation failed: {d}'.format(d=split_list))
        exit(0)

    if options.proxy:
        proxy = {
            'http': 'socks5h://%s' % options.proxy,
            'https': 'socks5h://%s' % options.proxy
        }
    else:
        proxy = {}

    if options.engines:
        for engine in options.engines.split(','):
            if engine.lower() in support_engines:
                engines.append(support_engines[engine])
    else:
        engines = [Baidu, Google, Bing, Yahoo]

    if options.domains is not None:
        for p in options.domains.split(','):
            p = p.strip().lower()
            re_domain = re.findall(r'^(([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,})$', p)
            if len(re_domain) > 0 and re_domain[0][0] == p and tldextract.extract(p).suffix != '':
                domains.append(p.strip())
            else:
                logger.error('Domain validation failed: {d}'.format(d=p))
    elif options.input and os.path.isfile(options.input):
        with open(options.input) as fh:
            for line_domain in fh:
                line_domain = line_domain.strip().lower()
                re_domain = re.findall(r'^(([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,})$', line_domain)
                if len(re_domain) > 0 and re_domain[0][0] == line_domain and tldextract.extract(line_domain).suffix != '':
                    domains.append(line_domain)
                else:
                    logger.error('Domain validation failed: {d}'.format(d=line_domain))
    else:
        logger.error('Please input vaild parameter. ie: "esd -d feei.cn" or "esd -f /Users/root/domains.txt"')

    if 'esd' in os.environ:
        debug = os.environ['esd']
    else:
        debug = False
    logger.info('Debug: {d}'.format(d=debug))
    logger.info('--skip-rsc: {rsc}'.format(rsc=skip_rsc))

    logger.info('Total target domains: {ttd}'.format(ttd=len(domains)))
    try:
        for d in domains:
            esd = EnumSubDomain(d, response_filter, skip_rsc=skip_rsc, debug=debug, split=split, engines=engines, proxy=proxy,
                                multiresolve=multiresolve, shodan_key=skey, fofa=fofa_struct, zoomeye=zoomeye_struct, censys=censys_struct)
            esd.run()
    except KeyboardInterrupt:
        print('', end='\n')
        logger.info('Bye :)')
        exit(0)


if __name__ == '__main__':
    main()
