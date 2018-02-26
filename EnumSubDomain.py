# -*- coding: utf-8 -*-

"""
    EnumSubDomain
    ~~~~~~~~~~~~~

    Implements enumeration sub domains

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/EnumSubdomain
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import os
import time
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
        self.data = {}
        self.domain = domain
        dns_servers = [
            '223.5.5.5',
            '223.6.6.6',
            '119.29.29.29',
        ]
        self.loop = asyncio.get_event_loop()
        self.resolver = aiodns.DNSResolver(loop=self.loop, nameservers=dns_servers)
        self.project_directory = os.path.abspath(os.path.dirname(__file__))

    def load_sub_domain_dict(self):
        with open('{dir}/data/subdomain.txt'.format(dir=self.project_directory)) as f:
            return [line.strip() for line in f]

    async def query(self, sub):
        try:
            ret = await self.resolver.query('{sub}.{domain}'.format(sub=sub, domain=self.domain), 'A')
        except aiodns.error.DNSError as e:
            err_code, err_msg = e.args[0], e.args[1]
            # 1: DNS server returned answer with no data
            # 4: Domain name not found
            if err_code not in [1, 4]:
                logger.info(e)
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
        subs = self.load_sub_domain_dict()

        tasks = []
        for sub in subs:
            task = asyncio.ensure_future(self.query(sub))
            task.add_done_callback(self.callback)
            tasks.append(task)
        self.loop.run_until_complete(asyncio.wait(tasks))
        logger.info('Total domain: {td}'.format(td=len(self.data)))
        time_consume = time.time() - start_time
        logger.info('Time consume: {tc}s'.format(tc=round(time_consume, 3)))


if __name__ == '__main__':
    esd = EnumSubDomain('qq.com')
    esd.start()
