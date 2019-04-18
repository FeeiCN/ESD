# -*- coding: utf-8 -*-

"""
    ESD
    ~~~

    Implements ESD setup

    sudo python setup.py sdist bdist_wheel
    sudo twine upload dist/ESD-0.0.x

    :author:    Feei <feei@feei.cn>
    :homepage:  https://github.com/FeeiCN/ESD
    :license:   GPL, see LICENSE for more details.
    :copyright: Copyright (c) 2018 Feei. All rights reserved
"""
import setuptools
from ESD.banner import Banner

__version__ = Banner().__version__

with open('README.md', 'r') as f:
    long_description = f.read()

setuptools.setup(
    name='ESD',
    version=__version__,
    author='Feei',
    author_email='feei@feei.cn',
    description='Enumeration sub domains(枚举子域名)',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/FeeiCN/ESD',
    packages=setuptools.find_packages(),
    install_requires=[
        'aiodns',
        'aiohttp',
        'async-timeout',
        'colorlog',
        'requests',
        'uvloop',
        'backoff',
        'dnspython',
        'tldextract',
        'shodan',
        'tqdm',
        'colorama',
        'censys'
    ],
    classifiers=(
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    ),
    include_package_data=True,
    package_data={
        '': ['*.esd', '*.pem', '*.ini']
    },
    entry_points={
        'console_scripts': [
            'esd=ESD:main'
        ]
    }
)
