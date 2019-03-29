import re
import dns
import tldextract
from .logger import logger


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
