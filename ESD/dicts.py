import itertools
import math
import string
import re
import os


class Dicts(object):
    def __init__(self, debug=False, split=None):
        self.debug = debug
        self.split = split
        self.project_directory = os.path.abspath(os.path.dirname(__file__))
        self.general_dicts = []

    def generate_general_dicts(self, line):
        """
        Generate general subdomains dicts
        :param line:
        :return:
        """
        # Count letters of subdomain rule
        letter_count = line.count('{letter}')
        # According to RFC 1034/1035, Only letters, numbers and dashes(-) are allowed in domain name.
        letters = itertools.product(string.ascii_lowercase + '-', repeat=letter_count)
        letters = [''.join(l) for l in letters]
        # Count numbers of subdomain rule
        number_count = line.count('{number}')
        numbers = itertools.product(string.digits, repeat=number_count)
        numbers = [''.join(n) for n in numbers]
        for l in letters:
            iter_line = line.replace('{letter}' * letter_count, l)
            # According RFC 1034/1035, subdomain not allowed to dashes(-) at the beginning and end.
            iter_line = iter_line.strip('-')
            iter_line = re.sub(r'-+', '-', iter_line)
            if iter_line != '':
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
        """
        Load subdomains from files and dicts
        :return:
        """
        dicts = []
        if self.debug:
            path = '{pd}/subs-test.esd'.format(pd=self.project_directory)
        else:
            path = '{pd}/subs.esd'.format(pd=self.project_directory)
        with open(path, encoding='utf-8') as f:
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
                    # compatibility other dicts
                    line = line.strip('.')
                    dicts.append(line)
        dicts = list(set(dicts))

        # split dict
        if self.split is not None:
            s = self.split.split('/')
            dicts_choose = int(s[0])
            dicts_count = int(s[1])
            dicts_every = int(math.ceil(len(dicts) / dicts_count))
            dicts = [dicts[i:i + dicts_every] for i in range(0, len(dicts), dicts_every)][dicts_choose - 1]
            print(f'Sub domain dict split {dicts_count} and get {dicts_choose}st')

        # root domain
        dicts.append('@')

        return dicts
