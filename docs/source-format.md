# 网页归档资料源

各URL明确给定，来源不需要链接发现。/entry到/start到/middle到/page有三次重定向、四个HTTP响应；/gzip为压缩实体；/chunked为chunked传输分帧，/chunked-gzip同时带chunked分帧与gzip实体；/page含重复头及应脱敏的合成Set-Cookie；/loop为重定向环，/outside跳到范围外地址。HTTP服务默认Content-Length与正文一致，不自动解压。所有凭据和Cookie均虚构。

归档格式采用WARC 1.1，标准参考ISO 28500与IIPC WARC1.1说明。record-ID为urn:uuid，block-digest与payload-digest采用sha256:加Base32编码；request/response的Content-Type使用application/http及msgtype，响应块HTTP首部用CRLF。块摘要覆盖整个记录Content区，载荷摘要仅覆盖响应实体。metadata JSON引用相应request/response记录ID。warcinfo说明脱敏与传输分帧去除策略。回放可给出原始编码实体及Content-Encoding，或解压后去掉该编码头并更新长度，需明示采用方式；HTTP跳到记录ID回放不得重新联网。来源没有WARC写入、索引或回放功能。

## archive_lab实现约定

`archive_lab`在标准库之上实现上述格式，无第三方依赖，分为互不依赖内存状态的四部分：

- `warc.py`：WARC 1.1帧、UTC日期、UUID、Content-Length、块/载荷摘要；同一未压缩warc文件可连续存放多条记录，记录间以CRLF CRLF结束。
- `client.py`：裸socket的HTTP/1.1客户端，`Connection: close`，不自动跟随重定向、不按Content-Encoding透明解压；只去除chunked等传输分帧，压缩实体保持原字节。
- `archiver.py`：每一跳分别写request、response、metadata，首条为warcinfo；请求Authorization/Cookie与响应Set-Cookie不落盘，被脱敏头名写入对应metadata，摘要针对实际存下的字节。范围、环、跳数停止时只写说明性metadata，范围外那一跳不发请求。
- `validator.py`与`replay.py`：校验器只解析WARC文件本身，定位坏摘要、错长度、坏帧与悬空引用；回放服务只读、仅绑定环回，按记录ID工作，默认verbatim，`?decoded=1`按需解压并在响应头声明，脱敏记录通过`X-Warc-Redacted-Headers`与`?describe=1`展示资料属性。

崩溃恢复只截断当前warc文件末尾不完整或摘要不符的记录；索引（`*.idx.json`）只是缓存，始终可由WARC文件重建，空索引不会掩盖文件内已有记录。内容相同但URL或响应头不同的记录分别保存，不做revisit压缩。

