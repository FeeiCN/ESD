import re
import os
import tldextract
from optparse import OptionParser
from .banner import Banner
from .lib.logger import logger


class Parse(object):
    def parse(self):
        Banner().show()
        parser = OptionParser('Usage: python ESD.py -d feei.cn -F response_filter -p user:pass@host:port')
        parser.add_option('-d', '--domain', dest='domains', help='The domains that you want to enumerate')
        parser.add_option('-f', '--file', dest='input', help='Import domains from this file')
        parser.add_option('-F', '--filter', dest='filter', help='Response filter')
        parser.add_option('-s', '--skip-rsc', dest='skiprsc', help='Skip response similary compare', action='store_true', default=False)
        parser.add_option('-S', '--split', dest='split', help='Split the dict into several parts', default='1/1')
        parser.add_option('-p', '--proxy', dest='proxy', help='Use socks5 proxy to access Google and Yahoo')
        parser.add_option('--skey', '--shodan-key', dest='shodankey', help='Define the api of shodan')
        parser.add_option('--fkey', '--fofa-key', dest='fofakey', help='Define the key of fofa')
        parser.add_option('--femail', '--fofa-email', dest='fofaemail', help='The email of your fofa account')
        parser.add_option('--zusername', '--zoomeye-username', dest='zoomeyeusername', help='The username of your zoomeye account')
        parser.add_option('--zpassword', '--zoomeye-password', dest='zoomeyepassword', help='The password of your zoomeye account')
        parser.add_option('--cuid', '--censys-uid', dest='censysuid', help="The uid of your censys account")
        parser.add_option('--csecret', '--censys-secret', dest='censyssecret', help='The secret of your censys account')
        (options, args) = parser.parse_args()

        domains = []
        response_filter = options.filter
        skip_rsc = options.skiprsc
        split_list = options.split.split('/')
        split = options.split
        skey = options.shodankey

        fofa_struct = {
            'fkey': options.fofakey,
            'femail': options.fofaemail,
        }

        zoomeye_struct = {
            'username': options.zoomeyeusername,
            'password': options.zoomeyepassword,
        }

        censys_struct = {
            'uid': options.censysuid,
            'secret': options.censyssecret,
        }

        try:
            if len(split_list) != 2 or int(split_list[0]) > int(split_list[1]):
                logger.error('Invaild split parameter,can not split the dict')
                split = None
        except:
            logger.error('Split validation failed: {d}'.format(d=split_list))
            exit(0)

        if options.proxy:
            proxy = {
                'http': 'socks5h://%s' % options.proxy,
                'https': 'socks5h://%s' % options.proxy
            }
        else:
            proxy = {}

        if options.domains is not None:
            for p in options.domains.split(','):
                p = p.strip().lower()
                re_domain = re.findall(r'^(([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,})$', p)
                if len(re_domain) > 0 and re_domain[0][0] == p and tldextract.extract(p).suffix != '':
                    domains.append(p.strip())
                else:
                    logger.error('Domain validation failed: {d}'.format(d=p))
        elif options.input and os.path.isfile(options.input):
            with open(options.input) as fh:
                for line_domain in fh:
                    line_domain = line_domain.strip().lower()
                    re_domain = re.findall(r'^(([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,})$', line_domain)
                    if len(re_domain) > 0 and re_domain[0][0] == line_domain and tldextract.extract(line_domain).suffix != '':
                        domains.append(line_domain)
                    else:
                        logger.error('Domain validation failed: {d}'.format(d=line_domain))
        else:
            logger.error('Please input vaild parameter. ie: "esd -d feei.cn" or "esd -f /Users/root/domains.txt"')

        if 'esd' in os.environ:
            debug = os.environ['esd']
        else:
            debug = False
        logger.info('Debug: {d}'.format(d=debug))
        logger.info('--skip-rsc: {rsc}'.format(rsc=skip_rsc))

        logger.info('Total target domains: {ttd}'.format(ttd=len(domains)))

        return domains, debug, response_filter, skip_rsc, split, skey, fofa_struct, zoomeye_struct, censys_struct, proxy
