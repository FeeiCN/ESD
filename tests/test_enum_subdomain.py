from EnumSubdomain import load_sub_domain_dict


def test_load_sub_domain_dict():
    assert 'www' in load_sub_domain_dict()
