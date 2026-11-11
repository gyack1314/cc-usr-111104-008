# 网页归档资料源

各URL明确给定，来源不需要链接发现。/start到/middle到/page有两次重定向、三个HTTP响应；/gzip为压缩实体；/page含重复头及应脱敏的合成Set-Cookie。HTTP服务默认Content-Length与正文一致，不自动解压。所有凭据和Cookie均虚构。

归档格式采用WARC 1.1，标准参考ISO 28500与IIPC WARC1.1说明。record-ID为urn:uuid，block-digest与payload-digest采用sha256:加Base32编码；request/response的Content-Type使用application/http及msgtype，响应块HTTP首部用CRLF。块摘要覆盖整个记录Content区，载荷摘要仅覆盖响应实体。metadata JSON引用相应request/response记录ID。warcinfo说明脱敏与传输分帧去除策略。回放可给出原始编码实体及Content-Encoding，或解压后去掉该编码头并更新长度，需明示采用方式；HTTP跳到记录ID回放不得重新联网。来源没有WARC写入、索引或回放功能。
