# ESD(Enumeration Sub Domain)

[![PyPI](https://img.shields.io/pypi/v/ESD.svg)](https://pypi.org/project/ESD/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/ESD.svg)
![license](https://img.shields.io/github/license/FeeiCN/ESD.svg)

[![asciicast](https://asciinema.org/a/15WhUe40eEhSbwAXZdf2RQdq9.png)](https://asciinema.org/a/15WhUe40eEhSbwAXZdf2RQdq9)

## 优势
#### 支持泛解析域名
> 基于`RSC`（响应相似度对比）技术对泛解析域名进行枚举（受网络质量、网站带宽等影响，速度会比较慢）

基于`aioHTTP`获取一个不存在子域名的响应内容，并将其和字典子域名响应进行相似度比对。
超过阈值则说明是同个页面，否则则为可用子域名，并对最终子域名再次进行响应相似度对比。

#### 更快的速度
> 基于`AsyncIO`异步协程技术对域名进行枚举（受网络和DNS服务器影响会导致扫描速度小幅波动，基本在250秒以内）

基于`AsyncIO`+`aioDNS`将比传统多进程/多线程/gevent模式快50%以上。
通过扫描`qq.com`，共`170083`条规则，找到`1913`个域名，耗时`163`秒左右，平均`1000+条/秒`。

#### 更全的字典
> 融合各类字典，去重后共170083条子域名字典

- 通用字典
    - 单字母、单字母+单数字、双字母、双字母+单数字、双字母+双数字、三字母、四字母
    - 单数字、双数字、三数字
- 域名解析商公布使用最多的子域名
    - DNSPod: dnspod-top2000-sub-domains.txt
- 其它域名爆破工具字典
    - subbrute: names_small.txt
    - subDomainsBrute: subnames_full.txt

#### 更多的收集渠道
- [X] 收集DNSPod接口泄露的子域名
- [X] 收集页面响应内容中出现的子域名
- [X] 收集跳转过程中的子域名
- [X] 收集HTTPS证书透明度子域名
- [X] 收集DNS域传送子域名
- [x] 收集搜索引擎子域名
- [x] 收集zoomeye、censys、fofa、shodan的接口结果

#### DNS服务器
- 解决各家DNS服务商对于网络线路出口判定不一致问题
- 解决各家DNS服务商缓存时间不一致问题
- 解决随机DNS问题，比如fliggy.com、plu.cn等
- 根据网络情况自动剔除无效DNS，提高枚举成功率

## 使用
仅在Python3下验证过
```bash
# 安装
pip install esd

# 升级
pip install esd --upgrade
```
**CLI命令行使用**
```bash
# 扫描单个域名
esd -d qq.com

# debug模式扫描单个域名
esd=debug esd -d qq.com

# 扫描多个域名（英文逗号分隔）
esd --domain qq.com,tencent.com

# 扫描单个域名且过滤子域名中单个特定响应内容
esd --domain mogujie.com --filter 搜本店

# 扫描单个域名且过滤子域名中多个特定响应内容
esd --domain mogujie.com --filter 搜本店,收藏店铺

# 扫描文件（文件中每行一个域名）
esd --file targets.txt

# 跳过相似度对比（开启这个选项会把所有泛解析的域名都过滤掉）
esd --domain qq.com --skip-rsc

# 使用搜索引擎进行子域名搜索（支持baidu、google、bing、yahoo，使用英文逗号分隔）
esd --domain qq.com --engines baidu,google,bing,yahoo

# 平均分割字典，加快爆破
esd --domain qq.com --split 1/4

# 使用DNS域传送漏洞获取子域名
esd --domain qq.com --dns-transfer

# 使用HTTPS证书透明度获取子域名
esd --domain qq.com --ca-info

```

**程序调用**
```python
from ESD import EnumSubDomain
domains = EnumSubDomain('feei.cn').run()
```

## 后续
- 提升扫描速度
- 支持三级子域名，多种组合更多可能性

## 参考
- http://feei.cn/esd
- https://github.com/aboul3la/Sublist3r
- https://github.com/TheRook/subbrute
- https://github.com/lijiejie/subDomainsBrute
