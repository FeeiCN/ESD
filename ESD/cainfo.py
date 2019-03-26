# -*- coding: utf-8 -*-

"""
    CAInfo
    ~~~~~~

    根据域名A记录通过HTTPS证书查询其支持的域名和子域名

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
import traceback


class CAInfo(object):
    def __init__(self, domain):
        self.domain = domain

    @staticmethod
    def query_a(domain):
        """
        查询根域名A记录
        :param domain: 被查询的域名(某些情况下根域名可能没有A记录，可尝试www的A记录)
        :return:
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        resolver = aiodns.DNSResolver(loop=loop)
        f = resolver.query(domain, 'A')
        result = loop.run_until_complete(f)
        # 可以多个IP都尝试下，但正常情况下没有区别
        return result[0].host

    @staticmethod
    def get_cert_domains(ip):
        """
        向IP的443端口查询支持的域名情况
        :param ip:
        :return:
        """
        s = socket.socket()
        s.settimeout(2)
        cert_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cacert.pem')
        connect = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=cert_path)
        connect.settimeout(2)
        connect.connect((ip, 443))
        cert_data = connect.getpeercert().get('subjectAltName')
        return cert_data

    def get_domains(self, only_subdomains=False):
        """
        根据HTTPS证书获取支持的域名
        :param only_subdomains: 是否只需要子域名，比如搜索baidu.com只需要*.baidu.com，不需要baidu.cn
        :return:
        """
        domains = []
        try:
            ip = self.query_a(self.domain)
            cert_domains = self.get_cert_domains(ip)
            for cert_domain in cert_domains:
                domain = cert_domain[1]
                if not domain.startswith('*'):
                    if only_subdomains:
                        if domain.endswith(self.domain):
                            domains.append(domain)
                    else:
                        domains.append(domain)
            return domains
        except Exception as e:
            return domains


if __name__ == '__main__':
    try:
        ret_domains = CAInfo('baidu.com').get_domains(only_subdomains=False)
        print(ret_domains)
    except Exception as e:
        traceback.print_exc()
