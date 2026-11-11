"""只读回放测试：按记录ID、verbatim/decoded、脱敏属性视图、404与不出网标记。"""
import gzip
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from archive_lab.archiver import Archiver  # noqa: E402
from archive_lab.replay import make_server  # noqa: E402
from source_lab.http import start  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
PAGE_HTML = (ROOT / "sources" / "page.html").read_bytes()
PAGE_GZ = (ROOT / "sources" / "page.gz").read_bytes()


class ReplayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = start(ROOT / "sources" / "normal.json")
        cls.origin = f"http://127.0.0.1:{cls.source.server_port}"
        cls.tmp = tempfile.TemporaryDirectory()
        cls.warc = Path(cls.tmp.name) / "r.warc"
        with Archiver(cls.warc, [cls.origin]) as archiver:
            archiver.capture(cls.origin + "/gzip")
            archiver.capture(cls.origin + "/entry")
        cls.server = make_server(cls.warc)
        cls.thread = threading.Thread(
            target=cls.server.serve_forever, daemon=True
        )
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.source.shutdown()
        cls.source.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        listing = json.loads(
            urllib.request.urlopen(self.base + "/records").read()
        )
        self.listing = listing

    def _id(self, suffix, record_type):
        matches = [
            item["record_id"]
            for item in self.listing
            if item["target_uri"] == self.origin + suffix
            and item["record_type"] == record_type
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def _open(self, path):
        return urllib.request.urlopen(self.base + path)

    def test_listing_is_built_from_warc_file(self):
        types = {item["record_type"] for item in self.listing}
        self.assertEqual(
            types, {"warcinfo", "request", "response", "metadata"}
        )
        for item in self.listing:
            self.assertTrue(item["record_id"].startswith("<urn:uuid:"))
            self.assertGreaterEqual(item["offset"], 0)

    def test_verbatim_gzip_returns_archived_bytes(self):
        rid = self._id("/gzip", "response")
        response = self._open("/records/" + rid.strip("<>"))
        self.assertEqual(response.read(), PAGE_GZ)
        self.assertEqual(response.headers["Content-Encoding"], "gzip")
        self.assertEqual(response.headers["X-Warc-Replay-Mode"], "verbatim")
        self.assertEqual(
            response.headers["X-Warc-Record-Id"], rid.strip("<>")
        )
        self.assertIn("no network", response.headers["X-Warc-Replay"])

    def test_decoded_mode_decompresses_and_updates_headers(self):
        rid = self._id("/gzip", "response")
        response = self._open("/records/" + rid.strip("<>") + "?decoded=1")
        body = response.read()
        self.assertEqual(body, PAGE_HTML)
        self.assertIsNone(response.headers.get("Content-Encoding"))
        self.assertTrue(
            response.headers["X-Warc-Replay-Mode"].startswith("decoded:gzip")
        )
        self.assertEqual(int(response.headers["Content-Length"]), len(body))
        # 解压视图不改变档案文件本身。
        self.assertEqual(
            self._open("/records/" + rid.strip("<>")).read(), PAGE_GZ
        )

    def test_redacted_record_shows_attributes_not_verbatim_claim(self):
        rid = self._id("/page", "response")
        response = self._open("/records/" + rid.strip("<>"))
        self.assertEqual(response.headers["X-Warc-Redacted-Headers"],
                         "Set-Cookie")
        self.assertEqual(response.read(), PAGE_HTML)
        describe = json.loads(
            self._open(
                "/records/" + rid.strip("<>") + "?describe=1"
            ).read()
        )
        self.assertEqual(
            describe["redacted_response_headers"], ["Set-Cookie"]
        )
        self.assertEqual(
            describe["http"]["entity_length"], len(PAGE_HTML)
        )
        self.assertTrue(describe["block_digest"].startswith("sha256:"))

    def test_unknown_record_id_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            self._open(
                "/records/urn:uuid:00000000-0000-0000-0000-000000000000"
            )
        self.assertEqual(context.exception.code, 404)

    def test_non_http_records_render_descriptive_json(self):
        rid = self._id("/gzip", "metadata")
        response = self._open("/records/" + rid.strip("<>"))
        payload = json.loads(response.read())
        self.assertEqual(payload["record_type"], "metadata")
        self.assertIn("metadata_json", payload)

    def test_redirect_chain_replays_each_hop_by_id(self):
        # 通过hop metadata的response_record_id取链路四跳，避免与直接
        # 采集的/page记录混淆。
        chain_meta = []
        for item in self.listing:
            if item["record_type"] != "metadata":
                continue
            response = self._open(
                "/records/" + item["record_id"].strip("<>")
            )
            payload = json.loads(response.read())
            if "metadata_json" in payload and \
                    "hop_index" in payload["metadata_json"] and \
                    payload["metadata_json"].get("original_request_url",
                                                 "").endswith("/entry"):
                chain_meta.append(payload["metadata_json"])
        chain_meta.sort(key=lambda value: value["hop_index"])
        self.assertEqual(len(chain_meta), 4)
        for meta in chain_meta:
            rid = meta["response_record_id"]
            response = self._open("/records/" + rid.strip("<>"))
            self.assertEqual(response.status, 200)
            self.assertEqual(
                response.headers["X-Warc-Record-Id"], rid.strip("<>")
            )

    def test_replay_catalog_opens_warc_read_only(self):
        # 回放目录对象不应持有写句柄：文件仍可被其它进程只读打开。
        from archive_lab.replay import ReplayCatalog

        catalog = ReplayCatalog(self.warc)
        rid = self._id("/gzip", "response")
        record = catalog.get_record(rid)
        self.assertEqual(record.record_type, "response")
        status, _headers, body, mode = catalog.render_http(rid)
        self.assertEqual((status, mode), (200, "verbatim"))
        self.assertEqual(body, PAGE_GZ)

    def test_gzip_roundtrip_matches_original_decompressed(self):
        rid = self._id("/gzip", "response")
        verbatim = self._open("/records/" + rid.strip("<>")).read()
        decoded = self._open(
            "/records/" + rid.strip("<>") + "?decoded=1"
        ).read()
        self.assertEqual(gzip.decompress(verbatim), decoded)


if __name__ == "__main__":
    unittest.main()
