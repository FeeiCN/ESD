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
通过扫描`qq.com`，共`661593`条规则，找到`3442`个域名，耗时`15`分钟左右。

更新于2021年9月，经实测多个DNS Server做了请求数限制，大并发下存在大量连接超时和异常导致遗漏情况大幅增加，目前通过限制DNS服务器以及并发数来解决，因此建议不要过于追求速度，通过设计更合理的触发时间来解决速度变慢问题。

#### 更全的字典
> 融合各类字典，去重后共620328条子域名字典

- 通用字典
- 域名解析商公布使用最多的子域名
- 其它域名爆破工具字典

#### 更多的收集渠道
- [X] 收集DNSPod接口泄露的子域名
- [X] 收集页面响应内容中出现的子域名
- [X] 收集跳转过程中的子域名
- [X] 收集HTTPS证书透明度子域名
- [X] 收集DNS域传送子域名

#### DNS服务器
- 解决各家DNS服务商对于网络线路出口判定不一致问题
- 解决各家DNS服务商缓存时间不一致问题
- 解决随机DNS问题，比如fliggy.com、plu.cn等
- 根据网络情况自动剔除无效DNS，提高枚举成功率

## 使用

```bash
# 安装
pip install esd
```

**CLI命令行使用**
```bash
# 扫描单个域名
esd -d qq.com
```

**程序调用**
```python
from ESD import EnumSubDomain
domains = EnumSubDomain('feei.cn').run()
```

## 文档
- https://yuque.com/esd
