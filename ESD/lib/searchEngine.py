import re
import time
import random
import requests
import threading
from urllib.parse import urlparse
from collections import Counter
from .logger import logger


class EngineBase(threading.Thread):
    def __init__(self, base_url, domain, q, verbose, proxy):
        threading.Thread.__init__(self)
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
                subdomain = urlparse(link).netloc
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
                subdomain = urlparse(link).netloc
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
                subdomain = urlparse(link).netloc
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
                subdomain = urlparse(link).netloc
                if subdomain.endswith(self.domain):
                    subdomain_list.append(subdomain)
                    if subdomain not in self.subdomains and subdomain != self.domain:
                        found_newdomain = True
                        logger.info('{engine_name}: {subdomain}'.format(engine_name=self.engine_name, subdomain=subdomain))
                        self.subdomains.append(subdomain.strip())
        except Exception:
            pass
        if not found_newdomain and subdomain_list:
            self.findsubs(subdomain_list)
        return links

    def findsubs(self, subdomains):
        count = Counter(subdomains)
        subdomain1 = max(count, key=count.get)
        count.pop(subdomain1, "None")
        subdomain2 = max(count, key=count.get) if count else ''
        return (subdomain1, subdomain2)
