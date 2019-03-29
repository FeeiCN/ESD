from shodan import Shodan
from shodan.cli.helpers import get_api_key
from .logger import logger
import requests
import base64
import json
from urllib.parse import urlparse
import censys.certificates
import os,re


# 使用shodan接口进行枚举，但经测试并不能增加多少成果
class ShodanEngine(object):
    def __init__(self, skey, conf, domain):
        self.domain = domain
        self.conf = conf
        self.skey = skey
        self.api = None

    # 初始化shodan的api
    def initialize(self, base_dir):
        if self.skey:
            logger.info('Initializing the shodan api.')
            result = os.system('shodan init {skey}'.format(skey=self.skey))
            if result:
                logger.warning('Initializ failed, please check your key.')
                return False
            self.conf.set("shodan", "shodan_key", self.skey)
            self.conf.write(open(base_dir + "/key.ini", "w"))
            self.api = Shodan(get_api_key())
        else:
            from click.exceptions import ClickException
            try:
                key = None if get_api_key() == '' else get_api_key()
                if key:
                    self.api = Shodan(key)
                else:
                    return False
            except ClickException as e:
                logger.warning('The shodan api is empty so you can not use shodan api.')
                return False
        return True

    def search(self):
        subs = list()
        result = self.api.search('hostname:{domain}'.format(domain=self.domain))
        for service in result['matches']:
            domain = service['hostnames'][0]
            subs.append(domain.rsplit(self.domain, 1)[0].strip('.'))
        return set(subs)


# fofa的sdk不支持python3，就只能调用restful api了，但是挖掘成果比shodan多
class FofaEngine(object):
    def __init__(self, fofa_struct, conf, domain):
        self.base_url = "https://fofa.so/api/v1/search/all?email={email}&key={key}&qbase64={domain}"
        self.email = fofa_struct['femail']
        self.fkey = fofa_struct['fkey']
        self.domain = base64.b64encode(domain.encode('utf-8')).decode('utf-8')
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.8',
            'Accept-Encoding': 'gzip',
        }
        self.timeout = 30
        self.conf = conf

    def initialize(self, base_dir):
        if self.fkey is not None and self.email is not None:
            self.conf.set("fofa", "fofa_key", self.fkey)
            self.conf.set("fofa", "fofa_email", self.email)
            self.conf.write(open(base_dir + "/key.ini", "w"))
            return True
        else:
            self.fkey = self.conf.items("fofa")[0][1]
            self.email = self.conf.items("fofa")[1][1]
            if self.fkey and self.email:
                return True
        return False

    def search(self):
        result = list()
        url = self.base_url.format(email=self.email, key=self.fkey, domain=self.domain)
        try:
            resp = requests.Session().get(url, headers=self.headers, timeout=self.timeout)
            json_resp = json.loads(resp.text)
            for res in json_resp['results']:
                domain = urlparse(res[0]).netloc
                result.append(domain.rsplit(self.domain, 1)[0].strip('.'))
        except Exception as e:
            result = []

        return result


# Zoomeye的效果还可以，但是比fofa还贵
class ZoomeyeEngine(object):
    def __init__(self, domain, zoomeye_struct, conf):
        self.headers = {
            "Authorization": "JWT {token}"
        }
        self.url = 'https://api.zoomeye.org/web/search?query=site:{domain}&page={num}'
        self.domain = domain
        self.zoomeye_struct = zoomeye_struct
        self.conf = conf

    def initialize(self, base_dir):
        username = self.zoomeye_struct['username']
        password = self.zoomeye_struct['password']
        if username != '' and password != '':
            resp = requests.Session().post(url='https://api.zoomeye.org/user/login', data=json.dumps(self.zoomeye_struct))
            resp_json = json.loads(resp.text)
        else:
            username = self.conf.items("zoomeye")[0][1]
            password = self.conf.items("zoomeye")[1][1]
            if username != '' and password != '':
                self.zoomeye_struct['username'] = username
                self.zoomeye_struct['password'] = password
                resp = requests.Session().post(url='https://api.zoomeye.org/user/login', data=json.dumps(self.zoomeye_struct))
                resp_json = json.loads(resp.text)
            else:
                return False
        if 'error' in resp_json.keys():
            # logger.warning('In Zoomeye' + resp_json['message'])
            return False
        self.conf.set("zoomeye", "zoomeye_username", username)
        self.conf.set("zoomeye", "zoomeye_password", password)
        self.conf.write(open(base_dir + "/key.ini", "w"))
        self.headers['Authorization'] = "JWT {token}".format(token=resp_json['access_token'])

        return True

    def search(self, num):
        url = self.url.format(domain=self.domain, num=num)
        resp = requests.Session().get(url=url, headers=self.headers)

        try:
            # zoomeye对于频繁的api调用会做限制，但是降低频率又会影响效率
            response = json.loads(resp.text)
        except Exception:
            response = None

        return response

    def enumerate(self):
        flag = True
        num = 1
        result = list()
        while flag:
            response = self.search(num)
            if response is None or 'error' in response.keys():
                # print(response)
                flag = False
            else:
                match_list = response["matches"]
                for block in match_list:
                    domain = block['site']
                    result.append(domain.rsplit(self.domain, 1)[0].strip('.'))
                num = num + 1
        return result


# censys的接口有点不稳定，经常出现timeout的情况
class CensysEngine(object):
    def __init__(self, domain, censys_struct, conf):
        self.domain = domain
        self.conf = conf
        self.censys_struct = censys_struct
        self.certificates = None
        self.fields = ['parsed.subject_dn']

    def initialize(self, base_dir):
        uid = self.censys_struct['uid']
        secret = self.censys_struct['secret']
        try:
            if uid is not None and secret is not None:
                self.certificates = censys.certificates.CensysCertificates(uid, secret)
            else:
                uid = self.conf.items("censys")[0][1]
                secret = self.conf.items("censys")[1][1]
                if uid != '' and secret != '':
                    self.certificates = censys.certificates.CensysCertificates(uid, secret)
                else:
                    return False

            self.conf.set("censys", "UID", uid)
            self.conf.set("censys", "SECRET", secret)
            self.conf.write(open(base_dir + "/key.ini", "w"))
        except Exception as e:
            return False

        return True

    def search(self):
        result = list()
        try:
            for c in self.certificates.search(self.domain, fields=self.fields):
                subject = c['parsed.subject_dn'].strip()
                reg_domain = self.domain.replace('.', '[.]')
                reg_text = r'(([-a-zA-Z0-9]+[.])*{reg_domain}$)'.format(reg_domain=reg_domain)
                match_list = re.findall(reg_text, subject)
                if match_list:
                    domain = match_list[0][0]
                    result.append(domain.rsplit(self.domain, 1)[0].strip('.'))
        except Exception as e:
            logger.warning(str(e))
            return result
        else:
            return result
