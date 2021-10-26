import itertools
import math
import string
import re
import os
from logger import logger


class Dicts(object):
    def __init__(self, debug=False, split=None):
        self.debug = debug
        self.split = split
        self.dicts_directory = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'dicts')
        # According to RFC 1034/1035, Only letters, numbers and dashes(-) are allowed in domain name.
        self.domain_whitelist_string = string.ascii_lowercase + '-' + string.digits

    @staticmethod
    def generate_general_dicts(domain_string, subdomain_length):
        """
        Generate general subdomains dicts
        :param domain_string:
        :param subdomain_length:
        :return:
        """
        # Iterable subdomains
        subdomains = []
        items = itertools.product(domain_string, repeat=subdomain_length)
        for item in items:
            item_string = ''.join(item)
            # According RFC 1034/1035, subdomain not allowed continuous dashes(-) and dash at the beginning and end.
            item_string = re.sub(r'-+', '-', item_string).strip('-')
            if item_string != '' and item_string not in subdomains:
                subdomains.append(item_string)
        return subdomains

    @staticmethod
    def read_dicts_file(path):
        dicts = []
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                # skip comments and space
                if '#' in line or line == '':
                    continue
                else:
                    dicts.append(line)
        return dicts

    def load_sub_domain_dict(self):
        """
        Load subdomains from files and dicts
        :return:
        """
        dicts = []
        # load dicts file
        if self.debug:
            path = 'subs-test.txt'
            full_path = os.path.join(self.dicts_directory, path)
            lists = self.read_dicts_file(full_path)
            dicts += list(set(lists))
            logger.info(f'Load Dicts: {path} Count: {len(lists)}')
        else:
            for path in os.listdir(self.dicts_directory):
                full_path = os.path.join(self.dicts_directory, path)
                lists = self.read_dicts_file(full_path)
                dicts += list(set(lists))
                logger.info(f'Load Dicts: {path} Count: {len(lists)}')

            # Generate general dicts
            generate_dicts = self.generate_general_dicts(self.domain_whitelist_string, 1)
            generate_dicts += self.generate_general_dicts(self.domain_whitelist_string, 2)
            generate_dicts += self.generate_general_dicts(self.domain_whitelist_string, 3)
            # generate_dicts += self.generate_general_dicts(string.ascii_lowercase, 4)
            generate_dicts += self.generate_general_dicts(string.digits, 4)

            logger.info(f'Load Dicts: generate_general.esd Count: {len(generate_dicts)}')

            dicts += generate_dicts

        # root domain
        dicts.append('@')

        # split dict
        if self.split is not None:
            s = self.split.split('/')
            dicts_choose = int(s[0])
            dicts_count = int(s[1])
            dicts_every = int(math.ceil(len(dicts) / dicts_count))
            dicts = [dicts[i:i + dicts_every] for i in range(0, len(dicts), dicts_every)][dicts_choose - 1]
            logger.info(f'Sub domain dict split {dicts_count} and get {dicts_choose}st')

        return list(set(dicts))
