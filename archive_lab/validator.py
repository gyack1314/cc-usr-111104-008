"""独立WARC校验器：不依赖采集器的任何内存状态或索引缓存。

校验内容：
- WARC 1.1帧结构、版本行、记录结束标记、Content-Length与实际字节；
- 每条记录的WARC-Block-Digest与（存在的）WARC-Payload-Digest；
- 必需首部（ID/UTC日期/类型/长度/块摘要）及record-id、日期格式；
- request/response块的HTTP结构与HTTP层Content-Length；
- response载荷摘要是否等于其实体字节摘要；
- metadata/request/response之间的WARC-Concurrent-To、Refers-To引用；
- warcinfo唯一且位于首条；
- 每个record-id唯一。

坏摘要或错长度的问题会定位到记录ID与文件偏移。
"""
import re
from dataclasses import dataclass

from .warc import (
    WarcFormatError,
    WarcTruncated,
    digest_matches,
    parse_one_record,
    sha256_digest,
)

UUID_RE = re.compile(r"^<urn:uuid:[0-9a-fA-F-]{36}>$")
DATE_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>0[1-9]|1[0-2])-"
    r"(?P<day>0[1-9]|[12]\d|3[01])T"
    r"(?P<hour>[01]\d|2[0-3]):(?P<minute>[0-5]\d):(?P<second>[0-5]\d)Z$"
)
KNOWN_TYPES = {
    "warcinfo",
    "request",
    "response",
    "metadata",
    "revisit",
    "resource",
    "conversion",
}
REQUIRED = (
    "WARC-Type",
    "WARC-Date",
    "WARC-Record-ID",
    "Content-Length",
    "WARC-Block-Digest",
)


@dataclass
class Issue:
    severity: str
    code: str
    offset: int
    record_id: str
    message: str

    def to_dict(self):
        return {
            "severity": self.severity,
            "code": self.code,
            "offset": self.offset,
            "record_id": self.record_id,
            "message": self.message,
        }


def _split_http_head(block):
    marker = b"\r\n\r\n"
    pos = block.find(marker)
    if pos < 0:
        raise ValueError("HTTP块缺少首部/正文空行")
    return block[: pos + len(marker)], block[pos + len(marker):]


def _parse_http_headers(head):
    lines = head.split(b"\r\n")
    start_line = lines[0]
    headers = []
    for line in lines[1:]:
        if line == b"":
            break
        name, sep, value = line.partition(b":")
        if not sep:
            raise ValueError(f"HTTP首部行非法: {line!r}")
        headers.append(
            (name.decode("latin-1").strip(), value.decode("latin-1").strip())
        )
    return start_line, headers


def _check_response(block):
    """核对响应HTTP结构与实体长度，返回(状态行, 首部, 实体字节)。"""
    head, entity = _split_http_head(block)
    start_line, headers = _parse_http_headers(head)
    if not start_line.startswith(b"HTTP/"):
        raise ValueError("响应块状态行非法")
    for name, value in headers:
        if name.lower() == "content-length":
            declared = int(value)
            if declared != len(entity):
                raise ValueError(
                    f"HTTP Content-Length声明{declared}，"
                    f"实体实际{len(entity)}字节"
                )
    return start_line, headers, entity


def _check_request(block):
    head, _entity = _split_http_head(block)
    start_line, headers = _parse_http_headers(head)
    parts = start_line.split(b" ")
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/"):
        raise ValueError(f"请求行非法: {start_line!r}")
    if parts[0] not in (b"GET", b"HEAD", b"POST"):
        raise ValueError(f"不支持的请求方法: {parts[0]!r}")
    return headers


def validate_file(path):
    """返回(问题列表, 记录统计)。文件尾部不完整记为error而非静默接受。"""
    issues = []
    seen_offsets = {}
    counts = {}
    warcinfo_offsets = []
    records_seen = 0

    def add(severity, code, offset, record_id, message):
        issues.append(Issue(severity, code, offset, record_id or "-", message))

    with open(path, "rb") as handle:
        while True:
            try:
                record = parse_one_record(handle)
            except WarcTruncated as exc:
                add("error", "truncated-record", handle.tell(), "-", str(exc))
                break
            except WarcFormatError as exc:
                add("error", "malformed-frame", handle.tell(), "-", str(exc))
                break
            if record is None:
                break
            records_seen += 1
            rid = record.record_id
            seen_offsets[record.offset] = record
            counts[record.record_type] = counts.get(record.record_type, 0) + 1

            for name in REQUIRED:
                if record.header(name) is None:
                    add("error", "missing-header", record.offset, rid,
                        f"缺少必需WARC首部{name}")
            if rid and not UUID_RE.match(rid):
                add("error", "bad-record-id", record.offset, rid,
                    "WARC-Record-ID不是<urn:uuid:...>形式")
            if record.date and not DATE_RE.match(record.date):
                add("error", "bad-date", record.offset, rid,
                    "WARC-Date不是UTC YYYY-MM-DDTHH:MM:SSZ")
            if record.record_type not in KNOWN_TYPES:
                add("warning", "unknown-type", record.offset, rid,
                    f"未知WARC类型: {record.record_type}")
            other = [
                offset
                for offset, item in seen_offsets.items()
                if item.record_id == rid and offset != record.offset
            ]
            if other:
                add("error", "duplicate-record-id", record.offset, rid,
                    f"记录ID与偏移{other[0]}处重复")

            # 声明长度必须等于实际块长度。
            if record.content_length != len(record.block):
                add("error", "bad-content-length", record.offset, rid,
                    f"Content-Length={record.content_length}，"
                    f"实际块={len(record.block)}字节")

            # 块摘要：最关键的完整性证据，坏摘要必须能被定位。
            if record.block_digest and not digest_matches(
                record.block, record.block_digest
            ):
                add("error", "bad-block-digest", record.offset, rid,
                    f"块摘要校验失败: 声明{record.block_digest}，"
                    f"实算{sha256_digest(record.block)}")

            # 载荷摘要与HTTP结构按记录类型分别核对。
            if record.record_type == "response":
                try:
                    _status, headers, entity = _check_response(record.block)
                    if record.payload_digest:
                        actual = sha256_digest(entity)
                        if actual != record.payload_digest:
                            add("error", "bad-payload-digest",
                                record.offset, rid,
                                f"载荷摘要校验失败: 声明"
                                f"{record.payload_digest}，实算{actual}")
                    for name, _value in headers:
                        token = name.lower()
                        if token == "set-cookie":
                            add("error", "forbidden-header", record.offset,
                                rid, "归档响应块中不得保存Set-Cookie")
                        if token == "transfer-encoding":
                            add("error", "framing-not-removed",
                                record.offset, rid,
                                "传输分帧首部应在归档前去除")
                except ValueError as exc:
                    add("error", "malformed-http", record.offset, rid,
                        str(exc))
            elif record.record_type == "request":
                try:
                    headers = _check_request(record.block)
                    for name, _value in headers:
                        if name.lower() in ("authorization", "cookie"):
                            add("error", "forbidden-header", record.offset,
                                rid, f"归档请求块中不得保存{name}")
                except ValueError as exc:
                    add("error", "malformed-http", record.offset, rid,
                        str(exc))
            elif record.payload_digest:
                actual = sha256_digest(record.block)
                if actual != record.payload_digest:
                    add("error", "bad-payload-digest", record.offset, rid,
                        f"载荷摘要校验失败: 声明{record.payload_digest}，"
                        f"实算{actual}")

            if record.record_type == "warcinfo":
                warcinfo_offsets.append(record.offset)

    # 引用完整性：Concurrent-To/Refers-To/Warcinfo-ID必须指向真实记录。
    all_ids = {item.record_id for item in seen_offsets.values()}
    for offset, record in sorted(seen_offsets.items()):
        rid = record.record_id
        for header_name in ("WARC-Concurrent-To", "WARC-Refers-To"):
            target = record.header(header_name)
            if target and target not in all_ids:
                add("error", "dangling-reference", offset, rid,
                    f"{header_name}指向不存在的记录{target}")
        warcinfo_ref = record.header("WARC-Warcinfo-ID")
        if (
            record.record_type != "warcinfo"
            and warcinfo_ref
            and warcinfo_ref not in all_ids
        ):
            add("error", "dangling-reference", offset, rid,
                f"WARC-Warcinfo-ID指向不存在的记录{warcinfo_ref}")

    if len(warcinfo_offsets) > 1:
        add("error", "multiple-warcinfo", warcinfo_offsets[1], "-",
            f"存在{len(warcinfo_offsets)}条warcinfo记录")
    if records_seen and warcinfo_offsets and warcinfo_offsets[0] != 0:
        add("error", "warcinfo-not-first", warcinfo_offsets[0], "-",
            "warcinfo记录必须位于文件首条")
    return issues, {"records": records_seen, "by_type": counts}
