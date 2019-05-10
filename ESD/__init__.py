from .engine import EnumSubDomain
from .lib.logger import logger
from .argparser import Parse


def main():
    domains, debug, response_filter, skip_rsc, split, skey, fofa_struct, zoomeye_struct, censys_struct, proxy = Parse().parse()

    try:
        for d in domains:
            esd = EnumSubDomain(d, response_filter, skip_rsc=skip_rsc, debug=False, split=split, proxy=proxy,
                                shodan_key=skey, fofa=fofa_struct, zoomeye=zoomeye_struct, censys=censys_struct)
            esd.run()
    except KeyboardInterrupt:
        logger.info('Bye :)')
        exit(0)
