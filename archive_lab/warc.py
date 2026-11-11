"""WARC 1.1帧格式、摘要、连续记录写入、截断恢复与文件级索引。

格式依据ISO 28500 (WARC 1.1)与IIPC WARC1.1说明：
- 记录 = 版本行 + WARC首部(CRLF) + 空行(CRLF) + 内容块 + CRLF CRLF；
- 记录ID为``<urn:uuid:...>``，日期为UTC ``YYYY-MM-DDTHH:MM:SSZ``；
- 块摘要覆盖整个Content区，载荷摘要只覆盖HTTP实体等载荷字节；
- 摘要标签为``sha256:``加RFC4648 Base32（无填充、小写），与常用工具一致。

本模块不了解HTTP语义，也不保存任何采集器内存状态：索引随时可以从
WARC文件本身重建。
"""
import base64
import hashlib
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

CRLF = b"\r\n"
RECORD_TERMINATOR = b"\r\n\r\n"
WARC_VERSION = "WARC/1.1"
DIGEST_ALGORITHM = "sha256"


class WarcFormatError(Exception):
    """WARC帧不符合1.1格式（首部缺失、长度不符、尾部不对齐等）。"""


class WarcTruncated(WarcFormatError):
    """文件在一条完整记录之前结束，属于崩溃留下的不完整末尾。"""


def utc_now_iso():
    """返回WARC要求的UTC秒级时间戳。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_record_id():
    """生成新的WARC-Record-ID值（含尖括号）。"""
    return f"<urn:uuid:{uuid.uuid4()}>"


def sha256_digest(data):
    """计算WARC摘要标签：sha256:加无填充小写Base32。"""
    raw = hashlib.sha256(data).digest()
    encoded = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    return f"{DIGEST_ALGORITHM}:{encoded}"


def digest_matches(data, label):
    """按标签声明的算法重新计算并核对摘要。"""
    try:
        algorithm, encoded = label.split(":", 1)
    except ValueError:
        return False
    if algorithm != DIGEST_ALGORITHM:
        return False
    raw = hashlib.sha256(data).digest()
    expected = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    return encoded.lower() == expected


@dataclass
class ParsedRecord:
    """从文件中解析出的一条WARC记录，全部按字节读取，不做正文文本解码。"""

    offset: int
    end_offset: int
    headers: list
    block: bytes
    record_id: str = ""
    record_type: str = ""
    target_uri: str = ""
    date: str = ""
    content_type: str = ""
    content_length: int = -1
    block_digest: str = ""
    payload_digest: str = ""
    warcinfo_id: str = ""
    concurrent_to: str = ""
    refers_to: str = ""
    ip_address: str = ""

    def header(self, name):
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None


@dataclass
class IndexEntry:
    """索引中的一条，字段全部来自WARC首部，可由文件重建。"""

    record_id: str
    offset: int
    end_offset: int
    record_type: str
    target_uri: str
    date: str
    content_type: str
    content_length: int
    block_digest: str
    payload_digest: str
    concurrent_to: str = ""

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "offset": self.offset,
            "end_offset": self.end_offset,
            "record_type": self.record_type,
            "target_uri": self.target_uri,
            "date": self.date,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "block_digest": self.block_digest,
            "payload_digest": self.payload_digest,
            "concurrent_to": self.concurrent_to,
        }

    @classmethod
    def from_dict(cls, value):
        return cls(**value)


_REQUIRED_HEADERS = (
    "WARC-Type",
    "WARC-Date",
    "WARC-Record-ID",
    "Content-Length",
    "WARC-Block-Digest",
)


def parse_one_record(handle):
    """从二进制文件当前位置解析一条记录。

    干净EOF返回``None``；内容不足或帧损坏抛出:class:`WarcTruncated`/
    :class:`WarcFormatError`。本函数只按字节解析，不改正文。
    """
    start = handle.tell()
    line = handle.readline()
    if line == b"":
        return None
    if line != (WARC_VERSION + "\r\n").encode("ascii"):
        raise WarcFormatError(f"偏移{start}处不是{WARC_VERSION}版本行: {line!r}")
    headers = []
    while True:
        raw = handle.readline()
        if raw == b"":
            raise WarcTruncated(f"偏移{start}的记录首部不完整")
        if raw == CRLF:
            break
        name, sep, value = raw.partition(b":")
        if not sep:
            raise WarcFormatError(f"偏移{start}处首部行缺少冒号: {raw!r}")
        headers.append(
            (name.decode("ascii").strip(), value.decode("latin-1").strip())
        )
    record = ParsedRecord(offset=start, end_offset=-1, headers=headers, block=b"")
    for key, value in headers:
        token = key.lower()
        if token == "warc-type":
            record.record_type = value
        elif token == "warc-record-id":
            record.record_id = value
        elif token == "warc-target-uri":
            record.target_uri = value
        elif token == "warc-date":
            record.date = value
        elif token == "content-type":
            record.content_type = value
        elif token == "content-length":
            record.content_length = int(value)
        elif token == "warc-block-digest":
            record.block_digest = value
        elif token == "warc-payload-digest":
            record.payload_digest = value
        elif token == "warc-warcinfo-id":
            record.warcinfo_id = value
        elif token == "warc-concurrent-to":
            record.concurrent_to = value
        elif token == "warc-refers-to":
            record.refers_to = value
        elif token == "warc-ip-address":
            record.ip_address = value
    missing = [
        name
        for name in _REQUIRED_HEADERS
        if record.header(name) is None
    ]
    if missing:
        raise WarcFormatError(f"偏移{start}的记录缺少首部: {', '.join(missing)}")
    if record.content_length < 0:
        raise WarcFormatError(f"偏移{start}的Content-Length非法")
    block = handle.read(record.content_length)
    if len(block) < record.content_length:
        raise WarcTruncated(
            f"记录{record.record_id or start}正文声明{record.content_length}字节，"
            f"实际只剩{len(block)}字节"
        )
    record.block = block
    tail = handle.read(len(RECORD_TERMINATOR))
    if len(tail) < len(RECORD_TERMINATOR):
        raise WarcTruncated(f"记录{record.record_id or start}缺少记录结束标记")
    if tail != RECORD_TERMINATOR:
        raise WarcFormatError(
            f"记录{record.record_id or start}结束标记不是CRLF CRLF: {tail!r}"
        )
    record.end_offset = handle.tell()
    return record


def iter_records(path):
    """只读遍历一个WARC文件的全部完整记录，供校验器与回放使用。"""
    with open(path, "rb") as handle:
        while True:
            record = parse_one_record(handle)
            if record is None:
                return
            yield record


def scan_complete(path):
    """扫描文件，返回(完整记录列表, 首个坏位置或None)。

    遇到任何帧错误或摘要不符即停止，调用方据此判断末尾是否需要截去。
    完整记录会重新核对块摘要，防止把损坏内容当成正常记录。
    """
    records = []
    with open(path, "rb") as handle:
        while True:
            try:
                record = parse_one_record(handle)
            except WarcFormatError:
                return records, handle.tell()
            if record is None:
                return records, None
            if not digest_matches(record.block, record.block_digest):
                return records, record.offset
            records.append(record)


def recover_truncated_tail(path):
    """崩溃恢复：只截去本文件最后一条不完整/损坏记录及其之后的字节。

    返回(保留记录数, 截去字节数)。已完整且摘要正确的记录绝不改动。
    """
    path = Path(path)
    if not path.exists() or path.stat().st_size == 0:
        return 0, 0
    records, bad_offset = scan_complete(path)
    valid_end = records[-1].end_offset if records else 0
    size = path.stat().st_size
    if bad_offset is None and valid_end == size:
        return len(records), 0
    with open(path, "r+b") as handle:
        handle.truncate(valid_end)
        handle.flush()
        os.fsync(handle.fileno())
    return len(records), size - valid_end


def build_index(path):
    """完全从WARC文件本身重建内存索引，不读取任何旁路状态。"""
    entries = {}
    order = []
    path = Path(path)
    if not path.exists():
        return entries, order
    for record in iter_records(path):
        entry = IndexEntry(
            record_id=record.record_id,
            offset=record.offset,
            end_offset=record.end_offset,
            record_type=record.record_type,
            target_uri=record.target_uri,
            date=record.date,
            content_type=record.content_type,
            content_length=record.content_length,
            block_digest=record.block_digest,
            payload_digest=record.payload_digest,
            concurrent_to=record.concurrent_to,
        )
        entries[record.record_id] = entry
        order.append(record.record_id)
    return entries, order


def index_sidecar_path(warc_path):
    return Path(str(warc_path) + ".idx.json")


def write_index_sidecar(warc_path, entries, order):
    """把索引缓存写到旁路JSON；该文件缺失或被清空都不影响档案本身。"""
    target = index_sidecar_path(warc_path)
    payload = {
        "warc": Path(warc_path).name,
        "note": "缓存索引，可随时由WARC文件重建，不得用于掩盖文件内已有记录",
        "records": [entries[key].to_dict() for key in order],
    }
    fd, name = tempfile.mkstemp(prefix=".idx-", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            import json

            handle.write(json.dumps(payload, ensure_ascii=False, indent=2))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, target)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@dataclass
class WarcWriter:
    """向未压缩warc文件连续追加WARC 1.1记录。

    打开时先做崩溃恢复并从文件重建索引，因此采集器重启不依赖任何内存
    状态，也不会信任可能为空的旁路索引。
    """

    path: Path
    _handle: object = field(default=None, init=False)
    _entries: dict = field(default_factory=dict, init=False)
    _order: list = field(default_factory=list, init=False)
    _warcinfo_id: str = field(default="", init=False)

    def __post_init__(self):
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        recover_truncated_tail(self.path)
        self._entries, self._order = build_index(self.path)
        if self._order:
            first = self._entries[self._order[0]]
            if first.record_type == "warcinfo":
                self._warcinfo_id = first.record_id
        self._handle = open(self.path, "ab")

    @property
    def warcinfo_id(self):
        return self._warcinfo_id

    @property
    def record_count(self):
        return len(self._order)

    def index(self):
        return [self._entries[key] for key in self._order]

    def write_record(
        self,
        record_type,
        content_type,
        block,
        target_uri=None,
        extra_headers=None,
        payload=None,
        compute_payload_digest=True,
    ):
        """写入一条记录，返回(记录ID, 偏移, 块摘要, 载荷摘要)。

        摘要针对实际存下的（已脱敏的）块与载荷计算。
        """
        record_id = new_record_id()
        block_digest = sha256_digest(block)
        payload_digest = ""
        if compute_payload_digest:
            payload_digest = sha256_digest(
                block if payload is None else payload
            )
        headers = [
            ("WARC-Type", record_type),
            ("WARC-Record-ID", record_id),
            ("WARC-Date", utc_now_iso()),
        ]
        if target_uri is not None:
            headers.append(("WARC-Target-URI", target_uri))
        if self._warcinfo_id:
            headers.append(("WARC-Warcinfo-ID", self._warcinfo_id))
        for key, value in extra_headers or []:
            headers.append((key, value))
        headers.extend(
            [
                ("Content-Type", content_type),
                ("Content-Length", str(len(block))),
                ("WARC-Block-Digest", block_digest),
            ]
        )
        if payload_digest:
            headers.append(("WARC-Payload-Digest", payload_digest))
        lines = [WARC_VERSION + "\r\n"]
        for key, value in headers:
            lines.append(f"{key}: {value}\r\n")
        lines.append("\r\n")
        offset = self._handle.tell()
        self._handle.write("".join(lines).encode("latin-1"))
        self._handle.write(block)
        self._handle.write(RECORD_TERMINATOR)
        self._handle.flush()
        entry = IndexEntry(
            record_id=record_id,
            offset=offset,
            end_offset=-1,
            record_type=record_type,
            target_uri=target_uri or "",
            date=headers[2][1],
            content_type=content_type,
            content_length=len(block),
            block_digest=block_digest,
            payload_digest=payload_digest,
            concurrent_to=dict(extra_headers or []).get("WARC-Concurrent-To", ""),
        )
        self._entries[record_id] = entry
        self._order.append(record_id)
        # 回填结束偏移并刷新旁路索引缓存。
        self._entries[record_id].end_offset = self._handle.tell()
        write_index_sidecar(self.path, self._entries, self._order)
        return record_id, offset, block_digest, payload_digest

    def write_warcinfo(self, block, target_uri=None):
        if self._warcinfo_id:
            raise WarcFormatError("一个WARC文件只能有一条warcinfo记录")
        record_id, offset, block_digest, payload_digest = self.write_record(
            "warcinfo",
            "application/warc-fields",
            block,
            target_uri=target_uri,
        )
        self._warcinfo_id = record_id
        # 后续记录需要引用warcinfo，补写后重建一次索引缓存。
        write_index_sidecar(self.path, self._entries, self._order)
        return record_id

    def close(self):
        if self._handle is not None:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
