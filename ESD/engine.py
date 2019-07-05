from .lib.basePackage import *
from .banner import Banner
from .lib import logger, CAInfo, DNSTransfer, DNSQuery, Google, Bing, Baidu, Yahoo, ZoomeyeEngine, FofaEngine, ShodanEngine, CensysEngine, DnsSec

# asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
loop = uvloop.new_event_loop()
asyncio.set_event_loop(loop)


class EnumSubDomain(object):
    def __init__(self, domain, response_filter=None, dns_servers=None, skip_rsc=False, debug=False,
                 split=None, proxy={}, process_bar=True, shodan_key=None,
                 fofa={'fkey': None, 'femail': None}, zoomeye={'username': None, 'password': None}, censys={'uid': None, 'secret': None}):
        self.project_directory = os.path.abspath(os.path.dirname(__file__))
        logger.info('Version: {v}'.format(v=Banner().__version__))
        logger.info('----------')
        logger.info('Start domain: {d}'.format(d=domain))
        self.engines = [Baidu, Bing, Google, Yahoo]
        self.proxy = proxy
        self.data = {}
        self.domain = domain
        self.skip_rsc = skip_rsc
        self.split = split
        self.skey = shodan_key
        self.fofa_struct = fofa
        self.conf = configparser.ConfigParser()
        self.zoomeye_struct = zoomeye
        self.censys_struct = censys
        self.process_bar = process_bar
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

    async def query(self, sub, is_brute=True):
        """
        Query domain
        :param sub:
        :return:
        """
        ret = None
        # root domain
        if sub == '@' or sub == '':
            sub_domain = self.domain
            v_sub_domain = ''
        else:
            sub = ''.join(sub.rsplit(self.domain, 1)).rstrip('.')
            sub_domain = '{sub}.{domain}'.format(sub=sub, domain=self.domain)
            x_sub_domain = "{sub}{random}".format(sub=sub ,random=random.randint(0, 9))
            v_sub_domain = '{sub}.{domain}'.format(sub=x_sub_domain, domain=self.domain)
        try:
            ret = await self.resolver.query(sub_domain, 'A')
            v_ret = await self.resolver.query(v_sub_domain, 'A') if v_sub_domain != '' else []
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
            v_domain_ips = [r.host for r in v_ret]
            # It is a wildcard domain name and
            # the subdomain IP that is burst is consistent with the IP
            # that does not exist in the domain name resolution,
            # the response similarity is discarded for further processing.
            if not is_brute:
                if sub != self.wildcard_sub:
                    self.data[sub_domain] = sorted(domain_ips)
                    self.count += 1
                    logger.info('{r} {sub} {ips}'.format(r=self.remainder, sub=sub_domain, ips=domain_ips))
            elif self.is_wildcard_domain and (sorted(self.wildcard_ips) == sorted(domain_ips) or set(domain_ips).issubset(self.wildcard_ips)):
                if self.skip_rsc:
                    logger.debug('{sub} maybe wildcard subdomain, but it is --skip-rsc mode now, it will be drop this subdomain in results'.format(sub=sub_domain))
                else:
                    logger.debug('{r} maybe wildcard domain, continue RSC {sub}'.format(r=self.remainder, sub=sub_domain, ips=domain_ips))
            else:
                # 有一些域名会对特定子域名做泛解析比如dev*.mogujie.com所以需要二次判断
                if sorted(domain_ips) == sorted(v_domain_ips) or set(v_domain_ips).issubset(domain_ips):
                    logger.debug("{v_sub}* is a wildcard subdomain too.".format(v_sub=sub_domain))
                else:
                    self.data[sub_domain] = sorted(domain_ips)
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
        if self.process_bar:
            for res in tqdm(self.limited_concurrency_coroutines(tasks, self.coroutine_count), bar_format="%s{l_bar}%s{bar}%s{r_bar}%s" % (Fore.YELLOW, Fore.YELLOW, Fore.YELLOW, Fore.RESET), total=tasks_num):
                await res
        else:
            for res in self.limited_concurrency_coroutines(tasks, self.coroutine_count):
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
            job = self.query(self.wildcard_sub, False)
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

        # CA subdomain info
        logger.info('Collect subdomains in CA...')
        ca_subdomains = CAInfo(self.domain).get_subdomains()
        if len(ca_subdomains):
            tasks = (self.query(sub, False) for sub in ca_subdomains)
            self.loop.run_until_complete(self.start(tasks, len(ca_subdomains)))
        logger.info('CA subdomain count: {c}'.format(c=len(ca_subdomains)))

        # DNS Transfer Vulnerability
        logger.info('Check DNS Transfer Vulnerability in {domain}'.format(domain=self.domain))
        transfer_info = DNSTransfer(self.domain).transfer_info()
        if len(transfer_info):
            logger.warning('DNS Transfer Vulnerability found in {domain}!'.format(domain=self.domain))
            tasks = (self.query(sub, False) for sub in transfer_info)
            self.loop.run_until_complete(self.start(tasks, len(transfer_info)))
        logger.info('DNS Transfer subdomain count: {c}'.format(c=len(transfer_info)))

        # Use search engines to enumerate subdomains (support Baidu,Bing,Google,Yahoo)
        logger.info('Enumerating subdomains with search engine')
        subdomains_queue = multiprocessing.Manager().list()
        enums = [enum(self.domain, q=subdomains_queue, verbose=False, proxy=self.proxy) for enum in self.engines]
        for enum in enums:
            enum.start()
        for enum in enums:
            enum.join()
        subdomains = set(subdomains_queue)
        if len(subdomains):
            tasks = (self.query(sub, False) for sub in subdomains)
            self.loop.run_until_complete(self.start(tasks, len(subdomains)))
        logger.info('Search engines subdomain count: {subdomains_count}'.format(subdomains_count=len(subdomains)))

        # Use shodan to enumerate subdomains (need key and money)
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.conf.read(base_dir + "/key.ini")
        shodan = ShodanEngine(self.skey, self.conf, self.domain)
        is_success = shodan.initialize(base_dir)
        if is_success:
            logger.info('Enumerating subdomains with Shodan')
            shodan_result = shodan.search()
            if len(shodan_result):
                tasks = (self.query(sub, False) for sub in shodan_result)
                self.loop.run_until_complete(self.start(tasks, len(shodan_result)))
            logger.info("Shodan subdomain count: {subdomains_count}".format(subdomains_count=len(shodan_result)))

        # Use fofa to enumerate subdomains (need key and money)
        fofa = FofaEngine(self.fofa_struct, self.conf, self.domain)
        is_success = fofa.initialize(base_dir)
        if is_success:
            logger.info("Enumerating subdomains with Fofa")
            fofa_result = fofa.search()
            if len(fofa_result):
                tasks = (self.query(sub, False) for sub in fofa_result)
                self.loop.run_until_complete(self.start(tasks, len(fofa_result)))
            logger.info("Fofa subdomain count: {subdomains_count}".format(subdomains_count=len(fofa_result)))

        # Use zoomeye to enumerate subdomains (need account or money)
        zoomeye = ZoomeyeEngine(self.domain, self.zoomeye_struct, self.conf)
        is_success = zoomeye.initialize(base_dir)
        if is_success:
            logger.info("Enumerating subdomains with Zoomeye")
            zoomeye_result = zoomeye.enumerate()
            if len(zoomeye_result):
                tasks = (self.query(sub, False) for sub in zoomeye_result)
                self.loop.run_until_complete(self.start(tasks, len(zoomeye_result)))
            logger.info("Zoomeye subdomain count: {subdomains_count}".format(subdomains_count=len(zoomeye_result)))

        censys = CensysEngine(self.domain, self.censys_struct, self.conf)
        is_success = censys.initialize(base_dir)
        if is_success:
            logger.info("Enumerating subdomains with Censys")
            censys_result = censys.search()
            if len(censys_result):
                tasks = (self.query(sub, False) for sub in censys_result)
                self.loop.run_until_complete(self.start(tasks, len(censys_result)))
            logger.info("Censys subdomain count: {subdomains_count}".format(subdomains_count=len(censys_result)))

        # Use dnssec to enumerate subdomains
        dnssec = DnsSec(self.domain, ['8.8.8.8'], 10, 'tcp')
        is_support_dnssec = dnssec.dns_sec_check()
        if is_support_dnssec:
            logger.info("Enumerating subdomains with DnsSec")
            zone_info = dnssec.ds_zone_walk()
            if len(zone_info):
                tasks = (self.query(sub, False) for sub in zone_info)
                self.loop.run_until_complete(self.start(tasks, len(zone_info)))
            logger.info("DnsSec subdomain count: {subdomains_count}".format(subdomains_count=len(zone_info)))

        if self.is_wildcard_domain and not self.skip_rsc:
            # Response similarity comparison
            self.wildcard_subs = list(set(subs))
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
