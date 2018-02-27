from ESD import EnumSubDomain


def test_load_sub_domain_dict():
    esd = EnumSubDomain('feei.cn')
    assert 'www' in esd.load_sub_domain_dict()


def test_generate_general_dict():
    esd = EnumSubDomain('feei.cn')
    rules = {
        '{letter}': 26,
        '{letter}{number}': 260,
        '{letter}{letter}': 676,
        '{letter}{letter}{number}': 6760,
        '{letter}{letter}{number}{number}': 67600,
        '{letter}{letter}{letter}': 17576,
        '{letter}{letter}{letter}{number}{number}': 1757600,
        '{number}': 10,
        '{number}{number}': 100,
        '{number}{number}{number}': 1000,
    }

    for k, v in rules.items():
        esd.general_dicts = []
        dicts = esd.generate_general_dicts(k)
        print(len(dicts), dicts)
        assert len(dicts) == v
