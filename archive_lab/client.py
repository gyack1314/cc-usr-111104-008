"""最小化HTTP/1.1客户端：禁用隐式重定向与透明解压。

与标准库高层客户端不同，本模块：
- 绝不自动跟随3xx，每一跳都由归档器显式决定并单独归档；
- 绝不依据Content-Encoding解压，gzip/deflate实体保持服务器返回的原字节；
- 只去除HTTP传输分帧（chunked、Connection: close定界），并把原始响应
  状态行、全部响应头（含重复头）以字节形式交回归档器；
- 正文一律按字节处理，不做任何文本解码。
"""
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

REDACTED_REQUEST_HEADERS = ("authorization", "cookie")
REDACTED_RESPONSE_HEADERS = ("set-cookie",)


@dataclass
class FetchResult:
    """一次显式请求的完整结果；网络失败时``connected``为False。"""

    url: str
    method: str
    host: str
    port: int
    ip_address: str = ""
    request_line: bytes = b""
    request_headers: list = field(default_factory=list)
    request_block: bytes = b""
    status_code: int = 0
    reason: str = ""
    response_headers: list = field(default_factory=list)
    raw_header_bytes: bytes = b""
    body: bytes = b""
    transfer_encoding: str = ""
    content_encoding: str = ""
    connected: bool = True
    error: str = ""
    location: str = ""


@dataclass
class _ResponseHead:
    status_code: int
    reason: str
    headers: list
    raw: bytes
    transfer_encoding: str
    content_encoding: str
    content_length: int = -1


def _read_line(handle):
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = handle.recv(1)
        if not chunk:
            if data:
                raise EOFError("响应首部中途连接关闭")
            return b""
        data += chunk
        if len(data) > 65536:
            raise ValueError("响应首部行过长")
    return data


def _read_exact(handle, size):
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = handle.recv(min(remaining, 65536))
        if not chunk:
            raise EOFError("响应正文声明长度未读完即关闭")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _dechunk(raw):
    """按RFC 7230去除chunked传输分帧，返回分帧内的实体原字节。"""
    output = []
    pos = 0
    while True:
        end = raw.find(b"\r\n", pos)
        if end < 0:
            raise ValueError("chunk大小行不完整")
        size_text = raw[pos:end].split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise ValueError(f"chunk大小非法: {size_text!r}") from exc
        pos = end + 2
        if size == 0:
            trailer_end = raw.find(b"\r\n", pos)
            while trailer_end >= 0:
                line = raw[pos:trailer_end]
                pos = trailer_end + 2
                if line == b"":
                    break
                trailer_end = raw.find(b"\r\n", pos)
            else:
                raise ValueError("结束块后的尾部不完整")
            return b"".join(output), pos
        if pos + size + 2 > len(raw):
            raise EOFError("chunk数据不完整")
        output.append(raw[pos:pos + size])
        if raw[pos + size:pos + size + 2] != b"\r\n":
            raise ValueError("chunk缺少CRLF结束")
        pos += size + 2


def _parse_head(handle):
    status_line = _read_line(handle)
    if not status_line:
        raise EOFError("服务器在返回响应前关闭连接")
    raw = status_line
    parts = status_line.rstrip(b"\r\n").split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/"):
        raise ValueError(f"状态行非法: {status_line!r}")
    try:
        status_code = int(parts[1])
    except ValueError as exc:
        raise ValueError(f"状态码非法: {status_line!r}") from exc
    reason = parts[2].decode("latin-1") if len(parts) == 3 else ""
    headers = []
    while True:
        line = _read_line(handle)
        if line == b"\r\n":
            break
        raw += line
        name, sep, value = line.rstrip(b"\r\n").partition(b":")
        if not sep:
            raise ValueError(f"响应首部行非法: {line!r}")
        headers.append(
            (name.decode("latin-1").strip(), value.decode("latin-1").strip())
        )
    transfer_encoding = ""
    content_encoding = ""
    content_length = -1
    for name, value in headers:
        token = name.lower()
        if token == "transfer-encoding":
            transfer_encoding = value
        elif token == "content-encoding":
            content_encoding = value
        elif token == "content-length" and content_length < 0:
            content_length = int(value)
    return _ResponseHead(
        status_code=status_code,
        reason=reason,
        headers=headers,
        raw=raw,
        transfer_encoding=transfer_encoding,
        content_encoding=content_encoding,
        content_length=content_length,
    )


def _read_body(handle, head):
    """按传输分帧读取正文；只去传输层编码，不动Content-Encoding。"""
    te = head.transfer_encoding.lower()
    if "chunked" in te:
        collected = []
        while True:
            size_line = _read_line(handle)
            if not size_line:
                raise EOFError("chunked正文提前结束")
            size_text = size_line.rstrip(b"\r\n").split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError as exc:
                raise ValueError(f"chunk大小非法: {size_text!r}") from exc
            data = _read_exact(handle, size)
            if _read_line(handle) != b"\r\n":
                raise ValueError("chunk数据后缺少CRLF")
            if size == 0:
                # 读完可选尾部首部。
                while True:
                    line = _read_line(handle)
                    if line in (b"\r\n", b""):
                        break
                break
            collected.append(data)
        return b"".join(collected)
    if head.content_length >= 0:
        return _read_exact(handle, head.content_length)
    # 没有分帧也没有长度：由连接关闭定界。
    chunks = []
    while True:
        chunk = handle.recv(65536)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def build_request_block(method, target, headers):
    """按给定行序构造请求字节块；header值不允许CRLF注入。"""
    lines = [f"{method} {target} HTTP/1.1\r\n"]
    for name, value in headers:
        if "\r" in value or "\n" in value or "\r" in name or "\n" in name:
            raise ValueError("HTTP首部禁止CRLF注入")
        lines.append(f"{name}: {value}\r\n")
    lines.append("\r\n")
    return "".join(lines).encode("latin-1")


def fetch(url, method="GET", extra_headers=None, timeout=10):
    """发起一次显式请求，不重定向、不解压，返回:class:`FetchResult`。

    网络层失败（DNS、连接拒绝、读超时等）不抛出，而是返回``connected``
    为False的结果，由归档器决定如何记录停止理由。
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"仅支持绝对http(s) URL: {url!r}")
    host = parts.hostname
    if parts.port is not None:
        port = parts.port
    else:
        port = 443 if parts.scheme == "https" else 80
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    headers = [
        ("Host", parts.netloc),
        ("User-Agent", "archive-lab/1.0 (+local-course-materials)"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Connection", "close"),
    ]
    for name, value in extra_headers or []:
        if name.lower() in ("host", "connection", "accept-encoding"):
            continue
        headers.append((name, value))
    request_block = build_request_block(method, target, headers)
    request_line = f"{method} {target} HTTP/1.1".encode("latin-1")
    result_kwargs = dict(
        url=url,
        method=method,
        host=host,
        port=port,
        request_line=request_line,
        request_headers=list(headers),
        request_block=request_block,
    )
    sock = None
    try:
        infos = socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM
        )
        last_error = None
        for family, socktype, proto, _canonname, sockaddr in infos:
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                ip_address = sockaddr[0]
                break
            except OSError as exc:
                last_error = exc
                if sock is not None:
                    sock.close()
                    sock = None
        if sock is None:
            raise OSError(str(last_error) or "无法解析或连接来源")
        if parts.scheme == "https":
            import ssl

            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=host)
        sock.sendall(request_block)
        head = _parse_head(sock)
        body = _read_body(sock, head)
        location = ""
        for name, value in head.headers:
            if name.lower() == "location":
                location = value
                break
        return FetchResult(
            **result_kwargs,
            ip_address=ip_address,
            status_code=head.status_code,
            reason=head.reason,
            response_headers=head.headers,
            raw_header_bytes=head.raw,
            body=body,
            transfer_encoding=head.transfer_encoding,
            content_encoding=head.content_encoding,
            location=location,
        )
    except (OSError, EOFError, ValueError) as exc:
        return FetchResult(
            **result_kwargs,
            status_code=0,
            reason="",
            response_headers=[],
            raw_header_bytes=b"",
            body=b"",
            transfer_encoding="",
            content_encoding="",
            connected=False,
            error=f"{type(exc).__name__}: {exc}",
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
