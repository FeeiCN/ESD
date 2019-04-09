import time
from ESD import EnumSubDomain
from ESD import DNSQuery
from difflib import SequenceMatcher

'''def test_load_sub_domain_dict():
    esd = EnumSubDomain('feei.cn')
    assert 'www' in esd.load_sub_domain_dict()


def test_generate_general_dict():
    start_time = time.time()
    esd = EnumSubDomain('feei.cn')
    rules = {
        '{letter}': 26,
        '{letter}{number}': 260,
        '{letter}{letter}': 676,
        '{letter}{letter}{number}': 6760,
        '{letter}{letter}{number}{number}': 67600,
        '{letter}{letter}{letter}': 17576,
        '{letter}{letter}{letter}{number}{number}': 1757600,
        '{letter}{letter}{letter}{letter}': 456976,
        '{number}': 10,
        '{number}{number}': 100,
        '{number}{number}{number}': 1000,
    }

    for k, v in rules.items():
        esd.general_dicts = []
        dicts = esd.generate_general_dicts(k)
        print(len(dicts), k)
        assert len(dicts) == v
    print(time.time() - start_time)


def test_rsc():
    a_html = """
<!DOCTYPE html><html lang="en"><head> <meta charset="UTF-8"/>
<meta http-equiv="Cache-Control" content="no-transform"/>
<meta name="renderer" content="webkit"/>
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
<link rel="dns-prefetch" href="//s2.mogucdn.com">
<link rel="dns-prefetch" href="//s11.mogucdn.com">
<link rel="dns-prefetch" href="//s17.mogucdn.com">
<link rel="dns-prefetch" href="//s10.mogucdn.com">
<link rel="dns-prefetch" href="//s14.mogucdn.com">
<meta name="copyright" content="mogujie.com"/>
<meta name="apple-itunes-app" content="app-id=452176796, app-argument="/>
<link rel="search" type="application/opensearchdescription+xml" href="//www.mogujie.com/opensearch.xml"/>
<link rel="icon" href="https://s10.mogucdn.com/mlcdn/c45406/170401_16fj5k6k4174bfd21d03a4gf6a7hg_48x48.png" type="image/x-icon"/>
 <title>蘑菇街-我的买手街</title> <meta name="description" content="美丽联合集团是女性时尚媒体和时尚消费平台，通过整合现在已有的资源，包括电商、社区、红人、内容等等，来服务于不同的女性用户。蘑菇街是集团旗下定位于年轻女性用户的时尚媒体与时尚消费类App，核心用户人群为 18-23 岁年轻女性用户。2015年，蘑菇街以当红明星李易峰和“我的买手街”的品牌定位，成功树立了自身以买手精选为核心理念的差异化品牌形象。2016年，迪丽热巴以首席体验官的身份代表广大用户加入蘑菇街，从而更好地为年轻女性用户提供从美妆、穿搭分享到时尚购物的一站式消费体验。">   <link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/global/assets/1.1.9/pc/common/base/css/index.css,mfp/meili-mgj-pc-header/assets/0.0.17/header.css,mfp/meili-mgj-pc-new-sidebar/assets/0.0.17/sidebar.css,mfp/meili-mgj-pc-footer/assets/0.0.9/footer.css,mfp/meili-mgj-top-nav-side-bar/assets/0.1.10/TopNavSideBar.css,mfp/meili-shoppc-header/assets/0.1.17/shopHeader.css"><link href="https://s10.mogucdn.com/__newtown/mogu-global/assets/pc/common/im/index.css-151cbbf6.css" rel="stylesheet" type="text/css"/> <link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/mgj-shop/assets/1.1.71/pages/pc/index/index.css"> <script> window.MOGU_ENV = "production"; window.MOGU_DEV = false;</script> <script src="//shieldironman.mogujie.com/co"></script> <script> window.isRender = true; PTP_PARAMS = {"ptp_cnt_a":"1","ptp_cnt_b":"shop_index_12345"}; </script> <style> .emptyShop{ width: 960px;             height: 400px;             margin: 0 auto;             background: #eee;             text-align: center;             margin-top: -30px; } .emptyShop p:first-child{ padding-top: 180px } </style></head><body>
<script src='https://s10.mogucdn.com/__/mfp/meili-base-logger/assets/1.3.6/logger.min.js'></script>
<div class="mgj_rightbar J_sidebar" data-ptp="_sidebar"></div><div id="header" class="site-top-header J_siteheader header_mid shop-info-search-header" data-ptp="_head"><div class="wrap clearfix"><div class="J-user-info-box"><div class="J-shop-user-info J-show-user-detail clearfix"></div><div class="J-shop-user-info-detail"></div><div class="shop-header-action clearfix"><a class="J-shop-follow shop-follow fl" rel="nofollow" href="javascript:;">收藏店铺</a><a href="javascript:;" class="chart fl clearfix" id="mogutalk_widget_box"></a><a href="javascript:;" class="shop-header-action-icon"></a></div></div><div class="search-nav-content clearfix"><!-- 搜索框 --> <div class="normal-search-content"> <div class="top_nav_search" id="nav_search_form"> <!--搜索框 --> <input type="submit" class="searchInShop J-searchInShop" value="搜本店"> <div class="search_inner_box clearfix"> <form action="/search/" method="get" id="top_nav_form"> <input type="text" id="headerSeachValue" data-tel="search_book" name="q" class="ts_txt fl" data-def="" value="" autocomplete="off" def-v="" /> <input type="submit" value="搜全站" class="ts_btn" /> <input type="hidden" name="t" value="bao" id="select_type" /> <input type="hidden" name="ptp" value="" /> </form> <div class="top_search_hint"></div> </div> </div> </div> <!-- 导航信息 --> <div class="site-top-nav J_sitenav"></div> </div></div></div><div class="J-shop-top-banner"></div><div class="J-shop-top-nav"></div><div id="views"></div><div id="emptyShop"></div><!-- esi --><input type="hidden" id="shopId" value="-1"/><input type="hidden" id="shopIdNumber" value="-1"/><input type="hidden" id="shopOwnerId" value="-1"/><input type="hidden" id="shopBaseUrl" value=""/><input type="hidden" id="shopSearchUrl" value=""/><script type="text/javascript"> window.___vData = { show: { 'img': 'https://s10.mogucdn.com/mlcdn/c45406/180116_47b5jd8ee5lkd2di865gb54ech80f_640x960.jpg_320x999.jpg', 'w': 320, 'h': 480 }, img: 'https://s10.mogucdn.com/mlcdn/c45406/180116_47b5jd8ee5lkd2di865gb54ech80f_640x960.jpg', clientUrl: 'https://shop.mogujie.com/detail/194n9yw?acm=3.ms.1_4_1lsjx9e.43.1185-698.ml9HAr1UDf.sd_117-swt_43-imt_6-t_ml9HAr1UFiPDf-lc_4-qid_4897-dit_31', priceFormat: '23', title: '英伦系带圆头小皮鞋复古牛津鞋学生春季新款学院风平底低跟单鞋' }; window.___shopId = document.getElementById('shopId') && document.getElementById('shopId').value || "-1"; if(window.location.search) { const localSearch = window.location.search.split('?'); const localParams = localSearch[1].split('&'); for (var i = 0; i < localParams.length; i++){ var tempParam = localParams[i].split('='); if(tempParam[0] === '__simulation__shopId') { window.___shopId = tempParam[1]; break; } }; }; window.___shopIdNumber = document.getElementById('shopIdNumber') && document.getElementById('shopIdNumber').value || "-1";</script><script type="text/javascript"> if (window.___shopId === "-1") { var $emptyShop=document.getElementById("emptyShop"); var child=document.getElementById("views"); child.parentNode.removeChild(child); $emptyShop.setAttribute('class', 'emptyShop'); var $p1 = document.createElement("p"); var $p2 = document.createElement("p"); $p1.innerHTML = '店铺不存在'; $p2.innerHTML = '将在5秒后自动<a href="//www.mogujie.com">返回首页</a>'; $emptyShop.appendChild($p1); $emptyShop.appendChild($p2); var timer = 5; setInterval(function(){ $p2.innerHTML = '<span>将在' + timer + '秒后自动<a href="//www.mogujie.com">返回首页</a></span>'; timer--; if(timer === 0){ logger.goTo('//www.mogujie.com'); }; }, 1000); };</script><div class="foot J_siteFooter" data-ptp="_foot"></div>
<script src='https://s10.mogucdn.com/__/mfp/meili-base-logger/assets/1.3.6/logger.min.js'></script>
<!--[if (IE gte 9)|(!IE)]><!--><script src="https://s10.mogucdn.com/__/mfp/meili-m/assets/1.6.1/m.mgj.js,mfp/meili-lib/assets/0.0.6/jquery.2.1.1.js,mfp/meili-lib/assets/0.0.6/jquery.migrate.1.2.1.js,mfp/meili-image-lazyload/assets/2.0.0/imageLazyloadUndepend.js,mfp/meili-mgj-top-nav-side-bar/assets/0.1.10/TopNavSideBar.js"></script><!--<![endif]--><!--[if lt IE 9]><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/es5-shim.js,mfp/meili-lib/assets/0.0.6/es5-sham.js,mfp/meili-lib/assets/0.0.6/console-polyfill.js,mfp/meili-lib/assets/0.0.6/json2.js,mfp/meili-m/assets/1.6.1/m.mgj.js,mfp/meili-lib/assets/0.0.6/jquery.1.7.2.js"></script><![endif]--><script type="text/javascript">  (function(){ var wWidth = $(window).width(); if(wWidth < 1212){ $('body').addClass('media_screen_960'); } else { $('body').addClass('media_screen_1200'); }  window.MoGu && $.isFunction(MoGu.set) && MoGu.set('initTime', (new Date()).getTime()); var ua = navigator.userAgent;  var is_plat_ipad = ua.match(/(iPad).*OS\s([\d_]+)/); if(is_plat_ipad) { $('body').addClass('media_ipad'); }  var is_plat_ipadApp = ua.indexOf('MogujieHD') >= 0 || ua.indexOf('Mogujie4iPad') >= 0 || location.href.indexOf('_atype=ipad') >= 0; if(is_plat_ipadApp) { $('body').addClass('media_ipad_app');  $('body').append('<style type="text/css">.header_2015,.header_nav,.foot .foot_wrap{display: none;}.foot{height: 0;background: none;}.back2top_wrap{height:0;width:0;overflow:hidden;opacity:0;}</style>');  setTimeout(function(){ $('.back2top_wrap').remove(); },1000) } })();</script><script src="https://s10.mogucdn.com/__/mfp/meili-trace/assets/1.2.5/trace.min.js,mfp/meili-mgj-pc-header/assets/0.0.17/header.js,mfp/meili-mgj-pc-new-sidebar/assets/0.0.17/sidebar.js,mfp/meili-mgj-pc-footer/assets/0.0.9/footer.js,mfp/meili-mgj-ie67-upgrade/assets/0.1.8/ie67upgrade.js,mfp/meili-base-mwp-js-sdk/assets/3.1.3/mwp.all.js,mfp/meili-shoppc-header/assets/0.1.17/shopHeader.js,mfp/meili-behavior-trace/assets/1.3.4/index.min.js"></script><script src="https://s10.mogucdn.com/__/newtown/mogu-global/assets/pc/common/im/index.js-b05a6f12.js,newtown/mogu-global/assets/pc/common/im/newcinfo.js-47757010.js"></script> <script type="text/javascript" src="https://s10.mogucdn.com/__/mfp/meili-all-libs-base/assets/2.1.0/vue.js"></script> <script type="text/javascript" src="https://s10.mogucdn.com/__/mfp/meili-all-libs-base/assets/2.1.0/vue-resource.js"></script> <script src="https://s10.mogucdn.com/__/mfp/meili-shoppc-module-itemwall/assets/0.0.8/index.all.min.js"></script><script src="https://s10.mogucdn.com/__/mfp/mgj-shop/assets/1.1.71/pages/pc/index/index.js"></script><script>
    (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
            (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
        m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
    })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

    ga('create', 'UA-25590490-1', 'auto');
    ga('send', 'pageview');
</script>
</body></html>"""
    b_html = """
<!DOCTYPE html><html lang="en"><head> <meta charset="UTF-8"/>
<meta http-equiv="Cache-Control" content="no-transform"/>
<meta name="renderer" content="webkit"/>
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1"/>
<link rel="dns-prefetch" href="//s2.mogucdn.com">
<link rel="dns-prefetch" href="//s11.mogucdn.com">
<link rel="dns-prefetch" href="//s17.mogucdn.com">
<link rel="dns-prefetch" href="//s10.mogucdn.com">
<link rel="dns-prefetch" href="//s14.mogucdn.com">
<meta name="copyright" content="mogujie.com"/>
<meta name="apple-itunes-app" content="app-id=452176796, app-argument="/>
<link rel="search" type="application/opensearchdescription+xml" href="//www.mogujie.com/opensearch.xml"/>
<link rel="icon" href="https://s10.mogucdn.com/mlcdn/c45406/170401_16fj5k6k4174bfd21d03a4gf6a7hg_48x48.png" type="image/x-icon"/>
 <title>蘑菇街-我的买手街</title> <meta name="description" content="美丽联合集团是女性时尚媒体和时尚消费平台，通过整合现在已有的资源，包括电商、社区、红人、内容等等，来服务于不同的女性用户。蘑菇街是集团旗下定位于年轻女性用户的时尚媒体与时尚消费类App，核心用户人群为 18-23 岁年轻女性用户。2015年，蘑菇街以当红明星李易峰和“我的买手街”的品牌定位，成功树立了自身以买手精选为核心理念的差异化品牌形象。2016年，迪丽热巴以首席体验官的身份代表广大用户加入蘑菇街，从而更好地为年轻女性用户提供从美妆、穿搭分享到时尚购物的一站式消费体验。">   <link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/global/assets/1.1.9/pc/common/base/css/index.css"><link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/meili-mgj-pc-header/assets/0.0.17/header.css"><link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/meili-mgj-pc-new-sidebar/assets/0.0.17/sidebar.css"><link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/meili-mgj-pc-footer/assets/0.0.9/footer.css"><link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/meili-mgj-top-nav-side-bar/assets/0.1.10/TopNavSideBar.css"><link rel="stylesheet" href="https://s10.mogucdn.com/__/mfp/meili-shoppc-header/assets/0.1.17/shopHeader.css"><link href="https://s10.mogucdn.com/__newtown/mogu-global/assets/pc/common/im/index.css-151cbbf6.css" rel="stylesheet" type="text/css"/> <link rel="stylesheet" href="//static.mogujie.com/__/mfp/mgj-shop/assets/1.1.70/pages/pc/index/index.css"> <script> window.MOGU_ENV = "test"; window.MOGU_DEV = true;</script> <script src="//shieldironman.mogujie.com/co"></script> <script> window.isRender = true; PTP_PARAMS = {"ptp_cnt_a":"1","ptp_cnt_b":"shop_index_12345"}; </script> <style> .emptyShop{ width: 960px;             height: 400px;             margin: 0 auto;             background: #eee;             text-align: center;             margin-top: -30px; } .emptyShop p:first-child{ padding-top: 180px } </style><script type="text/javascript">window.M_ENV="test"</script></head><body>
<script src='https://s10.mogucdn.com/__/mfp/meili-base-logger/assets/1.3.6/logger.min.js'></script>
<div class="mgj_rightbar J_sidebar" data-ptp="_sidebar"></div><div id="header" class="site-top-header J_siteheader header_mid shop-info-search-header" data-ptp="_head"><div class="wrap clearfix"><div class="J-user-info-box"><div class="J-shop-user-info J-show-user-detail clearfix"></div><div class="J-shop-user-info-detail"></div><div class="shop-header-action clearfix"><a class="J-shop-follow shop-follow fl" rel="nofollow" href="javascript:;">收藏店铺</a><a href="javascript:;" class="chart fl clearfix" id="mogutalk_widget_box"></a><a href="javascript:;" class="shop-header-action-icon"></a></div></div><div class="search-nav-content clearfix"><!-- 搜索框 --> <div class="normal-search-content"> <div class="top_nav_search" id="nav_search_form"> <!--搜索框 --> <input type="submit" class="searchInShop J-searchInShop" value="搜本店"> <div class="search_inner_box clearfix"> <form action="/search/" method="get" id="top_nav_form"> <input type="text" id="headerSeachValue" data-tel="search_book" name="q" class="ts_txt fl" data-def="" value="" autocomplete="off" def-v="" /> <input type="submit" value="搜全站" class="ts_btn" /> <input type="hidden" name="t" value="bao" id="select_type" /> <input type="hidden" name="ptp" value="" /> </form> <div class="top_search_hint"></div> </div> </div> </div> <!-- 导航信息 --> <div class="site-top-nav J_sitenav"></div> </div></div></div><div class="J-shop-top-banner"></div><div class="J-shop-top-nav"></div><div id="views"></div><div id="emptyShop"></div><!-- esi --><input type="hidden" id="shopId" value="-1"/><input type="hidden" id="shopIdNumber" value="-1"/><input type="hidden" id="shopOwnerId" value="-1"/><input type="hidden" id="shopBaseUrl" value=""/><input type="hidden" id="shopSearchUrl" value=""/><script type="text/javascript"> window.___vData = { show: { 'img': 'https://s10.mogucdn.com/mlcdn/c45406/180116_47b5jd8ee5lkd2di865gb54ech80f_640x960.jpg_320x999.jpg', 'w': 320, 'h': 480 }, img: 'https://s10.mogucdn.com/mlcdn/c45406/180116_47b5jd8ee5lkd2di865gb54ech80f_640x960.jpg', clientUrl: 'https://shop.mogujie.com/detail/194n9yw?acm=3.ms.1_4_1lsjx9e.43.1185-698.ml9HAr1UDf.sd_117-swt_43-imt_6-t_ml9HAr1UFiPDf-lc_4-qid_4897-dit_31', priceFormat: '23', title: '英伦系带圆头小皮鞋复古牛津鞋学生春季新款学院风平底低跟单鞋' }; window.___shopId = document.getElementById('shopId') && document.getElementById('shopId').value || "-1"; if(window.location.search) { const localSearch = window.location.search.split('?'); const localParams = localSearch[1].split('&'); for (var i = 0; i < localParams.length; i++){ var tempParam = localParams[i].split('='); if(tempParam[0] === '__simulation__shopId') { window.___shopId = tempParam[1]; break; } }; }; window.___shopIdNumber = document.getElementById('shopIdNumber') && document.getElementById('shopIdNumber').value || "-1";</script><script type="text/javascript"> if (window.___shopId === "-1") { var $emptyShop=document.getElementById("emptyShop"); var child=document.getElementById("views"); child.parentNode.removeChild(child); $emptyShop.setAttribute('class', 'emptyShop'); var $p1 = document.createElement("p"); var $p2 = document.createElement("p"); $p1.innerHTML = '店铺不存在'; $p2.innerHTML = '将在5秒后自动<a href="//www.mogujie.com">返回首页</a>'; $emptyShop.appendChild($p1); $emptyShop.appendChild($p2); var timer = 5; setInterval(function(){ $p2.innerHTML = '<span>将在' + timer + '秒后自动<a href="//www.mogujie.com">返回首页</a></span>'; timer--; if(timer === 0){ logger.goTo('//www.mogujie.com'); }; }, 1000); };</script><div class="foot J_siteFooter" data-ptp="_foot"></div>
<script src='https://s10.mogucdn.com/__/mfp/meili-base-logger/assets/1.3.6/logger.min.js'></script>
<!--[if (IE gte 9)|(!IE)]><!--><script src="https://s10.mogucdn.com/__/mfp/meili-m/assets/1.6.1/m.mgj.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/jquery.2.1.1.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/jquery.migrate.1.2.1.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-image-lazyload/assets/2.0.0/imageLazyloadUndepend.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-mgj-top-nav-side-bar/assets/0.1.10/TopNavSideBar.js"></script><!--<![endif]--><!--[if lt IE 9]><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/es5-shim.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/es5-sham.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/console-polyfill.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/json2.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-m/assets/1.6.1/m.mgj.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-lib/assets/0.0.6/jquery.1.7.2.js"></script><![endif]--><script type="text/javascript">  (function(){ var wWidth = $(window).width(); if(wWidth < 1212){ $('body').addClass('media_screen_960'); } else { $('body').addClass('media_screen_1200'); }  window.MoGu && $.isFunction(MoGu.set) && MoGu.set('initTime', (new Date()).getTime()); var ua = navigator.userAgent;  var is_plat_ipad = ua.match(/(iPad).*OS\s([\d_]+)/); if(is_plat_ipad) { $('body').addClass('media_ipad'); }  var is_plat_ipadApp = ua.indexOf('MogujieHD') >= 0 || ua.indexOf('Mogujie4iPad') >= 0 || location.href.indexOf('_atype=ipad') >= 0; if(is_plat_ipadApp) { $('body').addClass('media_ipad_app');  $('body').append('<style type="text/css">.header_2015,.header_nav,.foot .foot_wrap{display: none;}.foot{height: 0;background: none;}.back2top_wrap{height:0;width:0;overflow:hidden;opacity:0;}</style>');  setTimeout(function(){ $('.back2top_wrap').remove(); },1000) } })();</script><script src="https://s10.mogucdn.com/__/mfp/meili-trace/assets/1.2.5/trace.min.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-mgj-pc-header/assets/0.0.17/header.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-mgj-pc-new-sidebar/assets/0.0.17/sidebar.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-mgj-pc-footer/assets/0.0.9/footer.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-mgj-ie67-upgrade/assets/0.1.8/ie67upgrade.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-base-mwp-js-sdk/assets/3.1.3/mwp.all.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-shoppc-header/assets/0.1.17/shopHeader.js"></script><script src="https://s10.mogucdn.com/__/mfp/meili-behavior-trace/assets/1.3.4/index.min.js"></script><script src="https://s10.mogucdn.com/__/newtown/mogu-global/assets/pc/common/im/index.js-b05a6f12.js,newtown/mogu-global/assets/pc/common/im/newcinfo.js-47757010.js"></script> <script type="text/javascript" src="https://s10.mogucdn.com/__/mfp/meili-all-libs-base/assets/2.1.0/vue.js"></script> <script type="text/javascript" src="https://s10.mogucdn.com/__/mfp/meili-all-libs-base/assets/2.1.0/vue-resource.js"></script> <script src="https://s10.mogucdn.com/__/mfp/meili-shoppc-module-itemwall/assets/0.0.8/index.all.min.js"></script><script src="//static.mogujie.com/__/mfp/mgj-shop/assets/1.1.70/pages/pc/index/index.js"></script><script>
    (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
            (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
        m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
    })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

    ga('create', 'UA-25590490-1', 'auto');
    ga('send', 'pageview');
</script>
</body></html>"""
    ratio = SequenceMatcher(None, a_html, b_html).real_quick_ratio()
    assert ratio > 0.8

root_domain = 'python.org'
subs = ['planet.python.org', 'dinsdale.python.org', 'wiki', 'discuss.python.org', 'front', 'bugs']


def test_dns_query():
    before = time.time()
    enum = DNSQuery(root_domain,subs, root_domain)
    res = enum.dns_query()
    now = time.time()
    print(now - before)
    print(res)



test_dns_query()'''
domain_fuzz = EnumSubDomain('feei.cn',debug=True)
a = domain_fuzz.run()

