# -*- coding: utf-8 -*-
"""
    CA
    ~~

    Implements get domains by CA

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/ESD
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import os
import asyncio
import aiodns
import socket
import ssl


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
        cert_path = os.path.join(base_dir, '/cacert.pem')
        if not os.path.isfile(cert_path):
            print(f'error file path: {cert_path}')
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
