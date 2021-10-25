# -*- coding: utf-8 -*-
"""
    DNSTransfer
    ~~~~~~~~~~~

    Implements get domains by DNS Transfer

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/ESD
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import dns


class DNSTransfer(object):
    def __init__(self, domain):
        self.domain = domain

    def transfer_info(self):
        ret_zones = list()
        try:
            nss = dns.resolver.resolve(self.domain, 'NS')
            nameservers = [str(ns) for ns in nss]
            ns_addr = dns.resolver.resolve(nameservers[0], 'A')
            # dnspython 的 bug，需要设置 lifetime 参数
            zones = dns.zone.from_xfr(dns.query.xfr(ns_addr, self.domain, relativize=False, timeout=2, lifetime=2),
                                      check_origin=False)
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
