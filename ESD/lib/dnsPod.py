import requests
import re


class DNSPod(object):
    def __init__(self):
        pass

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
        except Exception as e:
            domains = []
        return domains
