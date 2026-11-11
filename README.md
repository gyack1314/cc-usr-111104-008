# 赛事公开网页的 WARC 归档与独立回放

此项目维护本地合成来源、协议资料及原始字节工具，用于复查机器人赛事与课程资料。所有名称、数据和地址都不代表真实组织或设备。

`source_lab` 提供资料服务，`sources` 保存业务样本，`workbench.raw_store` 按摘要存取原始字节。HTTP来源的每条路由可依次返回多个响应，最后一个响应会重复；服务仅绑定环回地址。详细数据格式见 [资料约定](docs/source-format.md)。

`archive_lab` 是Python标准库实现的WARC 1.1网页归档器、独立校验器与只读回放：按配置中明确给定的URL采集，不做链接发现或全站遍历；禁用隐式自动重定向与透明解压，每一跳分别归档；只允许配置的本地来源，范围外跳转只记录停止理由、不发那一跳请求。

使用 Python 3.11 或以上版本，无第三方Python依赖。在项目根目录执行：

```sh
python -m unittest discover -s tests -v
python -m compileall -q workbench source_lab archive_lab tests
python -m workbench.cli inspect sources
```

启动本地HTTP资料服务：

```sh
python -m source_lab.http sources/normal.json --port 8765
```

归档、校验、重建索引与回放（URL与允许来源写在配置JSON中，见`archive_lab/cli.py`文档字符串）：

```sh
python -m archive_lab.cli archive --config archive.json
python -m archive_lab.cli verify out/site.warc
python -m archive_lab.cli reindex out/site.warc
python -m archive_lab.cli replay out/site.warc --port 8790
# 回放：GET /records 列记录；GET /records/<urn:uuid:...> 按ID回放；
#       加 ?decoded=1 按需解压；加 ?describe=1 看资料属性与脱敏头名。
```

容器方式可执行 `docker build -t resource-source .`，随后 `docker run --rm resource-source python -m unittest discover -s tests -v`。服务地址只对本次运行有效，客户端应从配置取得地址。输出资料写入单独目录，原始样本保持只读。
