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
import string
import itertools
import datetime
import colorlog
import asyncio
import aiodns
import logging
from logging import handlers

log_path = 'logs'
if os.path.isdir(log_path) is not True:
    os.mkdir(log_path, 0o755)
logfile = os.path.join(log_path, 'ESD.log')

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

file_handler = handlers.RotatingFileHandler(logfile, maxBytes=(1048576 * 5), backupCount=7)
file_handler.setFormatter(formatter)

logger = colorlog.getLogger('ESD')
logger.addHandler(handler)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)


class EnumSubDomain(object):
    def __init__(self, domain):
        logger.info('----------')
        logger.info('Start domain: {d}'.format(d=domain))
        self.data = {}
        self.domain = domain
        dns_servers = []
        if not os.path.isfile('servers.esd'):
            logger.critical('ESD/servers.esd file not found!')
            exit(1)
        with open('servers.esd') as f:
            for s in f:
                dns_servers.append(s.strip())
        if len(dns_servers) == 0:
            logger.info('ESD/servers.esd not configured, The default will be used!')
            dns_servers = ['223.5.5.5', '223.6.6.6', '114.114.114.114']
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop, nameservers=dns_servers)
        self.project_directory = os.path.abspath(os.path.dirname(__file__))
        self.general_dicts = []

    def generate_general_dicts(self, line):
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
        dicts = []
        with open('{dir}/subs.esd'.format(dir=self.project_directory), encoding='utf-8') as f:
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
                    dicts.append(line)
        dicts = list(set(dicts))
        return dicts

    async def query(self, sub):
        full_domain = '{sub}.{domain}'.format(sub=sub, domain=self.domain)
        try:
            ret = await self.resolver.query(full_domain, 'A')
        except aiodns.error.DNSError as e:
            err_code, err_msg = e.args[0], e.args[1]
            # 1:  DNS server returned answer with no data
            # 4:  Domain name not found
            # 11: Could not contact DNS servers
            # 12: Timeout while contacting DNS servers
            if err_code not in [1, 4, 11, 12]:
                logger.info('{domain} {exception}'.format(domain=full_domain, exception=e))
            ret = None

        return sub, ret

    def callback(self, future):
        sub, result = future.result()
        if result is None:
            return
        full_domain = '{sub}.{domain}'.format(sub=sub, domain=self.domain)
        domain_ips = [s.host for s in result]
        self.data[full_domain] = sorted(domain_ips)
        logger.info('{domains} {ips}'.format(domains=full_domain, ips=domain_ips))

    def start(self):
        start_time = time.time()
        # 检查是否存在泛解析
        job = self.query('enumsubdomain-feei')
        sub, ret = self.loop.run_until_complete(job)
        if ret is not None and len([s.host for s in ret]) > 0:
            logger.critical('存在泛解析，无法通过枚举子域名爆破!')
            return
        subs = self.load_sub_domain_dict()
        logger.info('Sub domain dict count: {c}'.format(c=len(subs)))
        tasks = []
        for sub in subs:
            task = asyncio.ensure_future(self.query(sub))
            task.add_done_callback(self.callback)
            tasks.append(task)
        self.loop.run_until_complete(asyncio.wait(tasks))
        output_path = '{dir}/data/{domain}_{time}.esd'.format(dir=self.project_directory, domain=self.domain, time=datetime.datetime.now().strftime("%Y-%m_%d_%H-%M"))
        with open(output_path, 'w') as f:
            for domain, ips in self.data.items():
                f.write('{domain} : {ips}\n'.format(domain=domain, ips=','.join(ips)))
        logger.info('Output: {op}'.format(op=output_path))
        logger.info('Total domain: {td}'.format(td=len(self.data)))
        time_consume = time.time() - start_time
        logger.info('Time consume: {tc}s'.format(tc=round(time_consume, 3)))


if __name__ == '__main__':
    try:
        domains = []
        param = sys.argv[1].strip()
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
            esd = EnumSubDomain(d)
            esd.start()
    except KeyboardInterrupt:
        logger.info('Bye :)')
        exit(0)
