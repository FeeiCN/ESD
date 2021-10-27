#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    ESD
    ~~~

    Implements enumeration sub domains

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/ESD
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import sys

if __name__ == '__main__':
    # Check Python version, required python3 or higher because used asyncio feature
    if sys.version_info.major < 3:
        print('Python 3 or higher is required for ESD, upgrade your python please!')
        sys.exit(1)
    # Exception if before import Python3 code
    import EnumSubDomain

    EnumSubDomain.main()
