import dns


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
