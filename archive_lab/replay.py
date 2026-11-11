"""只读HTTP回放入口：按明确记录ID回放WARC中的归档资料。

安全边界：
- 只读打开WARC文件，索引在进程内从文件本身构建，不写任何文件；
- 不导入采集客户端，回放路径上不存在任何出网调用，不补资源；
- 只绑定环回地址。

回放模式：
- 默认``verbatim``：返回归档时存下的原始编码实体与Content-Encoding，
  逐字节可由块/载荷摘要验证；
- ``?decoded=1``：对gzip/deflate实体按需解压，移除Content-Encoding并
  更新Content-Length，响应头明示这是解压后视图；
- 被脱敏的记录显示资料属性（长度、摘要、内容类型、被移除头名），
  绝不声称逐字还原了原始线上响应。
"""
import gzip
import json
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .warc import build_index

REPLAY_MARKER = "X-Warc-Replay"
REPLAY_RECORD_ID = "X-Warc-Record-Id"
REPLAY_TARGET_URI = "X-Warc-Target-Uri"
REPLAY_DIGEST = "X-Warc-Payload-Digest"
REPLAY_REDACTED = "X-Warc-Redacted-Headers"
REPLAY_MODE = "X-Warc-Replay-Mode"


def _split_http(block):
    pos = block.find(b"\r\n\r\n")
    if pos < 0:
        raise ValueError("归档HTTP块缺少空行")
    head = block[:pos].decode("latin-1")
    entity = block[pos + 4:]
    lines = head.split("\r\n")
    start_line = lines[0]
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers.append((name.strip(), value.strip()))
    return start_line, headers, entity


def _decode_entity(entity, encoding):
    token = encoding.lower()
    if token == "gzip":
        return gzip.decompress(entity), "gzip"
    if token == "deflate":
        try:
            return zlib.decompress(entity), "deflate"
        except zlib.error:
            return zlib.decompress(entity, -zlib.MAX_WBITS), "deflate-raw"
    if token in ("", "identity"):
        return entity, "identity"
    raise ValueError(f"回放器不支持按需解压编码: {encoding}")


class ReplayCatalog:
    """从WARC文件构建的只读目录，供HTTP处理与程序化调用共用。"""

    def __init__(self, warc_path):
        self.warc_path = warc_path
        self.entries, self.order = build_index(warc_path)
        self._blocks = {}

    def list_records(self):
        return [self.entries[key].to_dict() for key in self.order]

    def get_record(self, record_id):
        if record_id not in self.entries:
            return None
        if record_id not in self._blocks:
            entry = self.entries[record_id]
            with open(self.warc_path, "rb") as handle:
                handle.seek(entry.offset)
                from .warc import parse_one_record

                record = parse_one_record(handle)
            if record is None or record.record_id != record_id:
                raise ValueError("WARC文件与索引不一致，请从文件重建索引")
            self._blocks[record_id] = record
        return self._blocks[record_id]

    def _metadata_for(self, record):
        """查找引用该响应记录的hop metadata，取脱敏头名等资料属性。"""
        for key in self.order:
            candidate = self.entries[key]
            if candidate.record_type != "metadata":
                continue
            meta_record = self.get_record(key)
            if meta_record.concurrent_to == record.record_id or \
                    meta_record.refers_to == record.record_id:
                try:
                    return json.loads(meta_record.block.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    return None
        return None

    def describe(self, record_id):
        """返回记录的资料属性视图（不重建被脱敏的原始内容）。"""
        record = self.get_record(record_id)
        if record is None:
            return None
        entry = self.entries[record_id]
        info = entry.to_dict()
        info["http"] = None
        if record.record_type in ("request", "response"):
            try:
                start_line, headers, entity = _split_http(record.block)
                info["http"] = {
                    "start_line": start_line,
                    "headers": headers,
                    "entity_length": len(entity),
                }
            except ValueError as exc:
                info["http_error"] = str(exc)
        elif record.record_type == "metadata":
            try:
                info["metadata_json"] = json.loads(
                    record.block.decode("utf-8")
                )
            except (ValueError, UnicodeDecodeError):
                pass
        metadata = self._metadata_for(record)
        if metadata:
            info["redacted_request_headers"] = metadata.get(
                "redacted_request_headers", []
            )
            info["redacted_response_headers"] = metadata.get(
                "redacted_response_headers", []
            )
            info["content_encoding_preserved"] = metadata.get(
                "content_encoding_preserved", ""
            )
        return info

    def render_http(self, record_id, decoded=False):
        """构造回放响应。返回(状态码, 头列表, 实体字节, 说明信息)。"""
        record = self.get_record(record_id)
        if record is None:
            return 404, [], b"", "record not found"
        if record.record_type != "response":
            payload = json.dumps(
                self.describe(record_id), ensure_ascii=False, indent=2
            ).encode("utf-8")
            return (
                200,
                [("Content-Type", "application/json; charset=utf-8")],
                payload,
                "non-http-record-described",
            )
        _start, headers, entity = _split_http(record.block)
        metadata = self._metadata_for(record) or {}
        redacted = metadata.get("redacted_response_headers", [])
        encoding = ""
        replay_headers = []
        for name, value in headers:
            if name.lower() == "content-encoding":
                encoding = value
            replay_headers.append((name, value))
        mode = "verbatim"
        if decoded and encoding and encoding.lower() not in ("", "identity"):
            entity, used = _decode_entity(entity, encoding)
            replay_headers = [
                (name, value)
                for name, value in replay_headers
                if name.lower() not in ("content-encoding", "content-length")
            ]
            replay_headers.append(("Content-Length", str(len(entity))))
            mode = f"decoded:{used}"
        # 每个回放响应都带来源与保真度标记，避免被误认为线上实时响应。
        replay_headers.extend(
            [
                (REPLAY_MARKER, "archived-read-only; no network access"),
                (REPLAY_RECORD_ID, record_id.strip("<>")),
                (REPLAY_MODE, mode),
                (REPLAY_DIGEST, record.payload_digest or record.block_digest),
            ]
        )
        if record.target_uri:
            replay_headers.append((REPLAY_TARGET_URI, record.target_uri))
        if redacted:
            replay_headers.append(
                (REPLAY_REDACTED, ", ".join(redacted))
            )
        status = 200
        return status, replay_headers, entity, mode


def make_server(warc_path, host="127.0.0.1", port=0):
    """创建环回只读回放服务器（不自动serve，调用方负责）。"""
    catalog = ReplayCatalog(warc_path)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _send(self, status, headers, body):
            sent = [
                (name, value)
                for name, value in headers
                if name.lower() != "content-length"
            ]
            sent.append(("Content-Length", str(len(body))))
            self.send_response(status)
            for name, value in sent:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self):
            self.do_GET()

        def do_GET(self):
            parts = urlsplit(self.path)
            query = parse_qs(parts.query)
            segments = [item for item in parts.path.split("/") if item]
            if segments == ["records"]:
                payload = json.dumps(
                    catalog.list_records(), ensure_ascii=False, indent=2
                ).encode("utf-8")
                self._send(
                    200,
                    [("Content-Type", "application/json; charset=utf-8")],
                    payload,
                )
                return
            if len(segments) == 2 and segments[0] == "records":
                raw_id = segments[1]
                if raw_id.startswith("urn:uuid:"):
                    record_id = f"<{raw_id}>"
                elif raw_id.startswith("<urn:uuid:") and raw_id.endswith(">"):
                    record_id = raw_id
                else:
                    self._send(
                        400,
                        [("Content-Type", "text/plain; charset=utf-8")],
                        b"record id must be urn:uuid:... form",
                    )
                    return
                if query.get("describe"):
                    info = catalog.describe(record_id)
                    if info is None:
                        self._send(404, [("Content-Type", "text/plain; charset=utf-8")],
                                   b"record id not found in archive")
                        return
                    payload = json.dumps(
                        info, ensure_ascii=False, indent=2
                    ).encode("utf-8")
                    self._send(
                        200,
                        [("Content-Type", "application/json; charset=utf-8")],
                        payload,
                    )
                    return
                status, headers, body, note = catalog.render_http(
                    record_id, decoded=bool(query.get("decoded"))
                )
                if status == 404:
                    self._send(
                        404,
                        [("Content-Type", "text/plain; charset=utf-8")],
                        b"record id not found in archive",
                    )
                    return
                self._send(status, headers, body)
                return
            self._send(
                404,
                [("Content-Type", "text/plain; charset=utf-8")],
                b"use /records or /records/<urn:uuid:...>",
            )

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.catalog = catalog
    return server
