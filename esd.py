from ESD.lib.logger import logger
from ESD.engine import EnumSubDomain
from ESD.argparser import Parse

def main():
    domains, debug, response_filter, skip_rsc, split, multiresolve, skey, fofa_struct, zoomeye_struct, censys_struct, proxy = Parse().parse()

    try:
        for d in domains:
            esd = EnumSubDomain(d, response_filter, skip_rsc=skip_rsc, debug=False, split=split, proxy=proxy,
                                multiresolve=multiresolve, shodan_key=skey, fofa=fofa_struct, zoomeye=zoomeye_struct, censys=censys_struct)
            esd.run()
    except KeyboardInterrupt:
        logger.info('Bye :)')
        exit(0)


if __name__ == '__main__':
    main()
