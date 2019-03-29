from ESD.argparser import *
from platform import platform
from ESD.engine import EnumSubDomain
from ESD.lib.logger import logger


def main():
    domains, debug, response_filter, skip_rsc, split, multiresolve, skey, fofa_struct, zoomeye_struct, censys_struct, proxy = Parse().parse()

    # macOS X high sierra高版本默认禁止动态fork，需要手动开启
    current_system = platform()
    if current_system.startswith('Darwin'):
        if 'OBJC_DISABLE_INITIALIZE_FORK_SAFETY' not in os.environ.keys():
            shell = os.environ['SHELL'].split('/')[-1]
            logger.warning('Use "echo \'export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES\'>>~/.{shell}rc&source ~/.{shell}rc" first in Mac OSX'.format(shell=shell))
            exit(-1)

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
