"""按明确URL采集并写入WARC 1.1的归档器。

设计约束（见docs/source-format.md与需求说明）：
- 只采集配置中明确给出的URL，不做链接发现、不遍历全站；
- 范围只允许配置的本地来源，跳到范围外时只记录停止理由，不发那一跳请求；
- 禁用隐式自动重定向与透明解压，每一跳分别归档request/response/metadata；
- 请求不保存Authorization/Cookie，响应不保存Set-Cookie，被脱敏头名写入metadata；
- HTTP传输分帧（chunked等）由客户端去除；Content-Encoding压缩实体保持
  服务器返回的原字节，归档块中保留该响应头并在warcinfo/metadata记录策略；
- 限制跳数并识别环；
- 内容相同但URL或响应头不同的记录各自独立保存，不做revisit压缩。
"""
import json
from dataclasses import dataclass
from urllib.parse import urlsplit, urljoin

from . import client
from .client import (
    REDACTED_REQUEST_HEADERS,
    REDACTED_RESPONSE_HEADERS,
    fetch,
)
from .warc import WarcWriter

STOP_OUT_OF_SCOPE = "out-of-scope"
STOP_REDIRECT_LOOP = "redirect-loop"
STOP_MAX_HOPS = "max-hops-exceeded"
STOP_FETCH_ERROR = "fetch-error"
STOP_NOT_REDIRECT = "terminal-response"

DEFAULT_MAX_HOPS = 5


@dataclass
class AllowedOrigin:
    """范围白名单中的一个来源：scheme://host[:port]，仅精确匹配。"""

    scheme: str
    host: str
    port: int

    @classmethod
    def parse(cls, value):
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"允许来源必须是绝对http(s)来源: {value!r}")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.path not in ("", "/") or parts.query:
            raise ValueError(f"允许来源只声明协议、主机和端口: {value!r}")
        return cls(parts.scheme, parts.hostname.lower(), port)

    def matches(self, url):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return (
            parts.scheme == self.scheme
            and parts.hostname.lower() == self.host
            and port == self.port
        )


def _filter_headers(headers, redacted_names):
    """拆分保留头与被脱敏头名；保留重复头，保持原顺序，不做合并。"""
    kept, removed = [], []
    for name, value in headers:
        if name.lower() in redacted_names:
            removed.append(name)
        else:
            kept.append((name, value))
    return kept, removed


def _encode_headers(headers):
    return "".join(f"{name}: {value}\r\n" for name, value in headers).encode(
        "latin-1"
    )


def build_request_block(result, redacted_names):
    """从实际发出的请求构造归档块，剔除脱敏头。"""
    kept, _ = _filter_headers(result.request_headers, redacted_names)
    lines = [result.request_line + b"\r\n"]
    lines.append(_encode_headers(kept))
    lines.append(b"\r\n")
    return b"".join(lines)


def _framing_headers(headers):
    return [
        name
        for name, _value in headers
        if name.lower() in ("transfer-encoding", "connection", "keep-alive")
    ]


def build_response_block(result, redacted_names):
    """构造最终归档的HTTP响应块。

    保留最终状态行与（脱敏后的）响应头及实体字节；传输分帧已由客户端
    去除，因此删除Transfer-Encoding等传输层首部并按实体长度校正
    Content-Length；Content-Encoding原样保留，压缩实体不解压。
    返回(响应块, 载荷实体字节, 被脱敏头名, 被移除的传输层头名)。
    """
    kept, removed = _filter_headers(result.response_headers, redacted_names)
    framing = _framing_headers(kept)
    filtered = [
        (name, value)
        for name, value in kept
        if name.lower() not in ("transfer-encoding", "connection", "keep-alive")
        and name.lower() != "content-length"
    ]
    filtered.append(("Content-Length", str(len(result.body))))
    head = (
        f"HTTP/1.1 {result.status_code} {result.reason}\r\n".encode("latin-1")
        + _encode_headers(filtered)
        + b"\r\n"
    )
    return head + result.body, result.body, removed, framing


def _warcinfo_block(config):
    """warcinfo记录块：application/warc-fields，说明全部归档策略。"""
    lines = [
        ("software", "archive-lab/1.0 (Python standard library only)"),
        ("format", "WARC file version 1.1; uncompressed; consecutive records"),
        ("conformsTo", "ISO 28500 WARC 1.1"),
        ("digest-algorithm", "sha256 with RFC4648 Base32 (no padding) labels"),
        (
            "http-redirect-policy",
            "manual single-hop requests; implicit auto-redirect disabled; "
            "each hop archived separately with hop relation and original URL",
        ),
        (
            "http-framing-policy",
            "client removes HTTP transfer framing (chunked, connection close); "
            "Transfer-Encoding/Connection headers omitted from archived response",
        ),
        (
            "content-encoding-policy",
            "Content-Encoding entity bytes preserved verbatim; no transparent "
            "decompression; replay must declare verbatim vs decoded mode",
        ),
        (
            "redaction-policy",
            "request Authorization/Cookie and response Set-Cookie are not stored; "
            "redacted header names recorded in metadata; digests cover stored bytes",
        ),
        (
            "scope-policy",
            "only configured allowed origins; out-of-scope hops are not requested "
            "and recorded as stop metadata",
        ),
        (
            "revisit-policy",
            "no revisit compression; identical bodies with different URLs or "
            "headers remain separate records",
        ),
        ("max-hops", str(config["max_hops"])),
    ]
    for origin in config["allowed_origins"]:
        lines.append(("allowed-origin", origin))
    return _encode_headers(lines)


def _metadata_bytes(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")


class Archiver:
    """一次会话内向一个WARC文件追加记录的采集器。"""

    def __init__(self, warc_path, allowed_origins, max_hops=DEFAULT_MAX_HOPS,
                 timeout=10):
        self.allowed = [AllowedOrigin.parse(item) for item in allowed_origins]
        if not self.allowed:
            raise ValueError("至少配置一个允许来源")
        self.max_hops = max_hops
        self.timeout = timeout
        self.writer = WarcWriter(warc_path)
        self._warcinfo_ready = bool(self.writer.warcinfo_id)
        self.captures = []

    def _ensure_warcinfo(self, base_url):
        if self._warcinfo_ready:
            return
        config = {
            "max_hops": self.max_hops,
            "allowed_origins": [
                f"{item.scheme}://{item.host}:{item.port}"
                for item in self.allowed
            ],
        }
        self.writer.write_warcinfo(
            _warcinfo_block(config), target_uri=base_url
        )
        self._warcinfo_ready = True

    def in_scope(self, url):
        return any(origin.matches(url) for origin in self.allowed)

    def _write_hop(self, result, hop_index, original_url, relation,
                   referrer_url):
        """归档一跳的request、response与说明性metadata三条记录。"""
        request_block = build_request_block(
            result, REDACTED_REQUEST_HEADERS
        )
        response_block, payload, removed_resp, framing = build_response_block(
            result, REDACTED_RESPONSE_HEADERS
        )
        _, removed_req = _filter_headers(
            result.request_headers, REDACTED_REQUEST_HEADERS
        )
        req_id, _offset, _bd, _pd = self.writer.write_record(
            "request",
            "application/http; msgtype=request",
            request_block,
            target_uri=result.url,
            extra_headers=[
                ("WARC-IP-Address", result.ip_address),
            ],
        )
        resp_id, _offset, _bd, payload_digest = self.writer.write_record(
            "response",
            "application/http; msgtype=response",
            response_block,
            target_uri=result.url,
            extra_headers=[
                ("WARC-IP-Address", result.ip_address),
                ("WARC-Concurrent-To", req_id),
            ],
            payload=payload,
        )
        metadata = {
            "hop_index": hop_index,
            "original_request_url": original_url,
            "actual_request_url": result.url,
            "referrer_url": referrer_url,
            "hop_relation": relation,
            "status_code": result.status_code,
            "ip_address": result.ip_address,
            "framing_removed": {
                "transfer_encoding_received": result.transfer_encoding,
                "headers_omitted_from_archive": framing,
            },
            "content_encoding_preserved": result.content_encoding,
            "redacted_request_headers": removed_req,
            "redacted_response_headers": removed_resp,
            "request_record_id": req_id,
            "response_record_id": resp_id,
            "response_payload_digest": payload_digest,
            "location_seen": result.location,
        }
        meta_id, _off, _bd, _pd = self.writer.write_record(
            "metadata",
            "application/json",
            _metadata_bytes(metadata),
            target_uri=result.url,
            extra_headers=[
                ("WARC-Concurrent-To", resp_id),
                ("WARC-Refers-To", resp_id),
            ],
        )
        self.captures.append(
            {
                "hop_index": hop_index,
                "url": result.url,
                "status": result.status_code,
                "request_id": req_id,
                "response_id": resp_id,
                "metadata_id": meta_id,
                "relation": relation,
            }
        )
        return req_id, resp_id, meta_id

    def _write_stop(self, url, hop_index, original_url, referrer_url,
                    reason, detail, relation):
        """范围外、环、跳数上限、网络失败等停止理由只写metadata。"""
        payload = {
            "hop_index": hop_index,
            "original_request_url": original_url,
            "candidate_url": url,
            "referrer_url": referrer_url,
            "hop_relation": relation,
            "stop_reason": reason,
            "detail": detail,
            "request_sent": False,
        }
        meta_id, _off, _bd, _pd = self.writer.write_record(
            "metadata",
            "application/json",
            _metadata_bytes(payload),
            target_uri=url,
        )
        self.captures.append(
            {
                "hop_index": hop_index,
                "url": url,
                "status": None,
                "metadata_id": meta_id,
                "stop_reason": reason,
                "relation": relation,
            }
        )
        return meta_id

    def capture(self, url):
        """采集一个明确给定的URL及其手动重定向链，返回跳次摘要。"""
        original_url = url
        self._ensure_warcinfo(url)
        visited = set()
        referrer = ""
        relation = "seed"
        hop = 0
        chain = []
        while True:
            if not self.in_scope(url):
                meta_id = self._write_stop(
                    url, hop, original_url, referrer,
                    STOP_OUT_OF_SCOPE,
                    "目标来源不在允许列表；未向该地址发送请求",
                    relation,
                )
                chain.append(
                    {"hop": hop, "url": url, "stop": STOP_OUT_OF_SCOPE,
                     "metadata_id": meta_id}
                )
                return chain
            if url in visited:
                meta_id = self._write_stop(
                    url, hop, original_url, referrer,
                    STOP_REDIRECT_LOOP,
                    f"重定向环：该地址已在本链中请求过: {sorted(visited)}",
                    relation,
                )
                chain.append(
                    {"hop": hop, "url": url, "stop": STOP_REDIRECT_LOOP,
                     "metadata_id": meta_id}
                )
                return chain
            if hop >= self.max_hops:
                meta_id = self._write_stop(
                    url, hop, original_url, referrer,
                    STOP_MAX_HOPS,
                    f"已达跳数上限{self.max_hops}，本跳未发送请求",
                    relation,
                )
                chain.append(
                    {"hop": hop, "url": url, "stop": STOP_MAX_HOPS,
                     "metadata_id": meta_id}
                )
                return chain
            visited.add(url)
            result = fetch(url, timeout=self.timeout)
            if not result.connected:
                meta_id = self._write_stop(
                    url, hop, original_url, referrer,
                    STOP_FETCH_ERROR, result.error, relation
                )
                chain.append(
                    {"hop": hop, "url": url, "stop": STOP_FETCH_ERROR,
                     "metadata_id": meta_id}
                )
                return chain
            req_id, resp_id, meta_id = self._write_hop(
                result, hop, original_url, relation, referrer
            )
            chain.append(
                {
                    "hop": hop,
                    "url": url,
                    "status": result.status_code,
                    "request_id": req_id,
                    "response_id": resp_id,
                    "metadata_id": meta_id,
                }
            )
            if result.status_code not in (301, 302, 303, 307, 308) \
                    or not result.location:
                return chain
            next_url = urljoin(url, result.location)
            referrer, url, relation = url, next_url, "redirect"
            hop += 1

    def close(self):
        self.writer.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
