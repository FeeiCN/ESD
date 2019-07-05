class Banner(object):
    def __init__(self):
        self.__version__ = '0.0.26b'

    def show(self):
        print("""\033[94m
                     ______    _____   _____  
                    |  ____|  / ____| |  __ \ 
                    | |__    | (___   | |  | |
                    |  __|    \___ \  | |  | |
                    | |____   ____) | | |__| |
                    |______| |_____/  |_____/\033[0m\033[93m
                # Enumeration sub domains @version: %s\033[92m
        """ % self.__version__)
