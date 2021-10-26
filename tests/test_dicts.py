#!/usr/bin/env python
# -*- coding: utf-8 -*-

import math
from ESD.dicts import Dicts


def test_generate_general_dicts():
    subs = Dicts().generate_general_dicts(Dicts().domain_whitelist_string, 1)
    assert 'a' in subs
    assert 'z' in subs
    assert '0' in subs
    assert '9' in subs
    assert '-' not in subs
    assert len(subs) == 36
    assert len(subs) < math.pow(len(Dicts().domain_whitelist_string), 1)

    subs = Dicts().generate_general_dicts(Dicts().domain_whitelist_string, 2)
    assert '01' in subs
    assert 'ab' in subs
    assert 'a-' not in subs
    assert len(subs) == 1332
    assert len(subs) < math.pow(len(Dicts().domain_whitelist_string), 2)

    subs = Dicts().generate_general_dicts(Dicts().domain_whitelist_string, 3)
    assert '001' in subs
    assert 'ab1' in subs
    assert 'p5p' in subs
    assert 'c-r' in subs
    assert 'abc' in subs
    assert '-ab' not in subs
    assert 'cd-' not in subs
    assert '--e' not in subs
    assert 'e--' not in subs
    assert len(subs) == 49284
    assert len(subs) < math.pow(len(Dicts().domain_whitelist_string), 3)

    import string
    # TOO HUGE 37^37=1.055513496E58
    # subs = Dicts().generate_general_dicts(string.ascii_lowercase, 4)
    # assert len(subs) == 49284

    subs = Dicts().generate_general_dicts(string.digits, 4)
    assert len(subs) == math.pow(len(string.digits), 4) == 10000


def test_load_sub_domain_dict():
    subs = Dicts().load_sub_domain_dict()
    assert 'trade' in subs
    assert 'admin' in subs
