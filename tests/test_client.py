"""HTTP客户端单元测试：不自动重定向、不透明解压、网络失败与注入防护。"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from archive_lab.archiver import (  # noqa: E402
    STOP_FETCH_ERROR,
    Archiver,
)
from archive_lab.client import build_request_block, fetch  # noqa: E402
from archive_lab.warc import iter_records  # noqa: E402
from source_lab.http import start  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


class ClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start(ROOT / "sources" / "normal.json")
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_fetch_does_not_follow_redirect(self):
        result = fetch(self.origin + "/start")
        self.assertTrue(result.connected)
        self.assertEqual(result.status_code, 302)
        self.assertTrue(result.location.endswith("/middle"))
        # 客户端停在第一跳，正文与Location都原样保留，由归档器决定下一步。
        self.assertNotIn("/middle", result.url)

    def test_fetch_does_not_transparently_decompress(self):
        result = fetch(self.origin + "/gzip")
        self.assertEqual(result.content_encoding, "gzip")
        self.assertEqual(
            result.body, (ROOT / "sources" / "page.gz").read_bytes()
        )
        self.assertEqual(result.body[:2], b"\x1f\x8b")

    def test_fetch_chunked_removes_only_transfer_framing(self):
        result = fetch(self.origin + "/chunked-gzip")
        self.assertIn("chunked", result.transfer_encoding.lower())
        # 分帧已去除，但gzip实体字节保留。
        self.assertEqual(
            result.body, (ROOT / "sources" / "page.gz").read_bytes()
        )
        self.assertEqual(result.content_encoding, "gzip")

    def test_fetch_connection_failure_is_result_not_exception(self):
        # 端口1上通常无服务；失败必须结构化返回而不是抛出。
        result = fetch("http://127.0.0.1:1/nope", timeout=2)
        self.assertFalse(result.connected)
        self.assertEqual(result.status_code, 0)
        self.assertTrue(result.error)

    def test_archiver_records_fetch_error_as_stop_metadata(self):
        # 白名单指向一个无服务的本地端口，采集应记录fetch-error而非崩溃。
        with tempfile.TemporaryDirectory() as tmp:
            warc = Path(tmp) / "err.warc"
            with Archiver(warc, ["http://127.0.0.1:1"], timeout=2) as archiver:
                chain = archiver.capture("http://127.0.0.1:1/page")
            self.assertEqual(chain[0]["stop"], STOP_FETCH_ERROR)
            records = list(iter_records(warc))
            stops = [
                r for r in records
                if r.record_type == "metadata" and b"stop_reason" in r.block
            ]
            self.assertEqual(len(stops), 1)
            self.assertIn(b"fetch-error", stops[0].block)
            # 网络失败时不产生request/response记录。
            self.assertEqual(
                [r.record_type for r in records].count("response"), 0
            )

    def test_crlf_injection_in_request_header_rejected(self):
        with self.assertRaises(ValueError):
            build_request_block(
                "GET", "/x",
                [("X-Bad", "v\r\nEvil: 1")],
            )
        with self.assertRaises(ValueError):
            build_request_block(
                "GET", "/x",
                [("X-Bad\n", "v")],
            )

    def test_invalid_url_rejected(self):
        with self.assertRaises(ValueError):
            fetch("not-an-absolute-url")
        with self.assertRaises(ValueError):
            fetch("ftp://127.0.0.1/x")


if __name__ == "__main__":
    unittest.main()
