#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ESD.dicts import Dicts


def test_generate_general_dicts():
    subs = Dicts().generate_general_dicts('{letter}')
    assert 'a' in subs
    assert 'z' in subs
    assert '-' not in subs
    subs = Dicts().generate_general_dicts('{number}')
    assert '0' in subs
    assert '9' in subs
    subs = Dicts().generate_general_dicts('{number}{number}')
    assert '01' in subs
    subs = Dicts().generate_general_dicts('{letter}{letter}{letter}')
    assert 'c-r' in subs
    assert 'abc' in subs
    assert '-ab' not in subs
    assert 'cd-' not in subs
    assert '--e' not in subs
    assert 'e--' not in subs
    subs = Dicts().generate_general_dicts('{letter}{letter}{number}')
    assert 'ab1' in subs
    subs = Dicts().generate_general_dicts('{letter}{number}{letter}')
    assert 'p5p' in subs


def test_load_sub_domain_dict():
    subs = Dicts().load_sub_domain_dict()
    assert '1111' in subs
    assert 'esd' in subs
    assert 'p5p' in subs
