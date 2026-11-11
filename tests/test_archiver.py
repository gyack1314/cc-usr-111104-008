"""归档器端到端测试：重复头、二进制、gzip、chunked、三跳、范围外、环、脱敏。"""
import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from archive_lab.archiver import (  # noqa: E402
    STOP_MAX_HOPS,
    STOP_OUT_OF_SCOPE,
    STOP_REDIRECT_LOOP,
    AllowedOrigin,
    Archiver,
)
from archive_lab.client import fetch  # noqa: E402
from archive_lab.validator import validate_file  # noqa: E402
from archive_lab.warc import iter_records  # noqa: E402
from source_lab.http import start  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "sources" / "normal.json"
PAGE_HTML = (ROOT / "sources" / "page.html").read_bytes()
PAGE_GZ = (ROOT / "sources" / "page.gz").read_bytes()
BINARY = (ROOT / "sources" / "binary.bin").read_bytes()


class ArchiveScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start(SCENARIO)
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.warc = Path(self.tmp.name) / "site.warc"

    def tearDown(self):
        self.tmp.cleanup()

    def archive(self, *paths, max_hops=5):
        with Archiver(self.warc, [self.origin], max_hops=max_hops) as archiver:
            for path in paths:
                archiver.capture(self.origin + path)
        return list(iter_records(self.warc))

    def responses_by_url(self, records):
        grouped = {}
        for record in records:
            if record.record_type == "response":
                grouped.setdefault(record.target_uri, []).append(record)
        return grouped

    def entity_of(self, record):
        return record.block[record.block.find(b"\r\n\r\n") + 4:]

    def test_three_hop_redirect_chain_each_hop_archived(self):
        records = self.archive("/entry")
        hops = [
            r for r in records
            if r.record_type == "response"
        ]
        self.assertEqual(
            [r.target_uri.rsplit("/", 1)[1] for r in hops],
            ["entry", "start", "middle", "page"],
        )
        self.assertEqual([json.loads(r.block)["hop_relation"]
                          for r in records if r.record_type == "metadata"
                          and b"hop_relation" in r.block],
                         ["seed", "redirect", "redirect", "redirect"])
        # 每一跳都有request/response/metadata三件套。
        self.assertEqual(
            sorted(self._counts(records).items()),
            [("metadata", 4), ("request", 4), ("response", 4),
             ("warcinfo", 1)],
        )
        metas = [json.loads(r.block) for r in records
                 if r.record_type == "metadata"]
        self.assertEqual(metas[0]["original_request_url"],
                         self.origin + "/entry")
        self.assertEqual(metas[1]["referrer_url"], self.origin + "/entry")
        issues, _stats = validate_file(self.warc)
        self.assertEqual([i.to_dict() for i in issues], [])

    @staticmethod
    def _counts(records):
        counts = {}
        for record in records:
            counts[record.record_type] = counts.get(record.record_type, 0) + 1
        return counts

    def test_duplicate_response_headers_are_both_kept(self):
        records = self.archive("/page")
        response = self.responses_by_url(records)[self.origin + "/page"][0]
        self.assertEqual(response.block.count(b"X-Note"), 2)
        self.assertIn(b"X-Note: one\r\n", response.block)
        self.assertIn(b"X-Note: two\r\n", response.block)

    def test_binary_body_is_verbatim_bytes(self):
        records = self.archive("/binary")
        response = self.responses_by_url(records)[self.origin + "/binary"][0]
        self.assertEqual(self.entity_of(response), BINARY)
        self.assertIn(b"\x00", self.entity_of(response))

    def test_gzip_entity_preserved_verbatim_with_encoding_header(self):
        records = self.archive("/gzip")
        response = self.responses_by_url(records)[self.origin + "/gzip"][0]
        self.assertEqual(self.entity_of(response), PAGE_GZ)
        self.assertIn(b"Content-Encoding: gzip\r\n", response.block)
        self.assertEqual(gzip.decompress(self.entity_of(response)), PAGE_HTML)
        meta = [json.loads(r.block) for r in records
                if r.record_type == "metadata"][0]
        self.assertEqual(meta["content_encoding_preserved"], "gzip")

    def test_chunked_framing_removed_but_entity_kept(self):
        records = self.archive("/chunked")
        response = self.responses_by_url(records)[self.origin + "/chunked"][0]
        self.assertEqual(self.entity_of(response), PAGE_HTML)
        self.assertNotIn(b"Transfer-Encoding", response.block)
        meta = [json.loads(r.block) for r in records
                if r.record_type == "metadata"][0]
        self.assertIn("Transfer-Encoding",
                      meta["framing_removed"]["headers_omitted_from_archive"])
        self.assertEqual(
            meta["framing_removed"]["transfer_encoding_received"].lower(),
            "chunked",
        )

    def test_chunked_gzip_framing_removed_compression_kept(self):
        records = self.archive("/chunked-gzip")
        response = self.responses_by_url(records)[
            self.origin + "/chunked-gzip"][0]
        self.assertEqual(self.entity_of(response), PAGE_GZ)
        self.assertNotIn(b"Transfer-Encoding", response.block)
        self.assertIn(b"Content-Encoding: gzip\r\n", response.block)
        self.assertEqual(gzip.decompress(self.entity_of(response)), PAGE_HTML)

    def test_set_cookie_redacted_and_named_in_metadata(self):
        records = self.archive("/page")
        response = self.responses_by_url(records)[self.origin + "/page"][0]
        self.assertNotIn(b"Set-Cookie", response.block)
        meta = [json.loads(r.block) for r in records
                if r.record_type == "metadata"][0]
        self.assertEqual(meta["redacted_response_headers"], ["Set-Cookie"])
        # 摘要针对实际存下的块，校验器应全部通过。
        issues, _ = validate_file(self.warc)
        self.assertEqual([i.code for i in issues], [])

    def test_request_authorization_and_cookie_redacted(self):
        result = fetch(
            self.origin + "/page",
            extra_headers=[("Authorization", "Bearer synthetic"),
                           ("Cookie", "sid=abc"),
                           ("X-Trace", "kept")],
        )
        self.assertTrue(result.connected)
        from archive_lab.archiver import build_request_block
        from archive_lab.client import REDACTED_REQUEST_HEADERS
        block = build_request_block(result, REDACTED_REQUEST_HEADERS)
        self.assertNotIn(b"Authorization", block)
        self.assertNotIn(b"Cookie", block)
        self.assertIn(b"X-Trace: kept\r\n", block)

    def test_out_of_scope_hop_recorded_but_not_requested(self):
        # 白名单只含一个不同端口的假来源，任何实际请求都发不出去。
        with Archiver(self.warc, ["http://127.0.0.1:1"]) as archiver:
            chain = archiver.capture(self.origin + "/outside")
        stop = [item for item in chain if "stop" in item]
        self.assertEqual(len(stop), 1)
        self.assertEqual(stop[0]["stop"], STOP_OUT_OF_SCOPE)
        records = list(iter_records(self.warc))
        stop_records = [
            json.loads(r.block) for r in records
            if r.record_type == "metadata" and b"stop_reason" in r.block
        ]
        self.assertEqual(len(stop_records), 1)
        self.assertEqual(stop_records[0]["candidate_url"],
                         self.origin + "/outside")
        self.assertFalse(stop_records[0]["request_sent"])
        # 范围内的/outside第一跳也不应被请求：白名单不含本服务来源。
        self.assertEqual(
            [r.record_type for r in records].count("response"), 0
        )

    def test_redirect_loop_detected(self):
        records = self.archive("/loop")
        stops = [json.loads(r.block) for r in records
                 if r.record_type == "metadata" and b"stop_reason" in r.block]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["stop_reason"], STOP_REDIRECT_LOOP)
        # 环上的URL只请求一次。
        loop_responses = [
            r for r in records
            if r.record_type == "response"
            and r.target_uri.endswith("/loop")
        ]
        self.assertEqual(len(loop_responses), 1)

    def test_max_hops_limit_stops_chain(self):
        # max_hops=2：允许/entry、/start两跳，第三跳/middle不再发送请求。
        records = self.archive("/entry", max_hops=2)
        stops = [json.loads(r.block) for r in records
                 if r.record_type == "metadata" and b"stop_reason" in r.block]
        self.assertEqual(len(stops), 1)
        self.assertEqual(stops[0]["stop_reason"], STOP_MAX_HOPS)
        self.assertEqual(stops[0]["candidate_url"], self.origin + "/middle")
        self.assertEqual(
            [r.record_type for r in records].count("response"), 2
        )

    def test_identical_bodies_different_urls_stay_separate(self):
        records = self.archive("/page", "/chunked")
        page_responses = [
            r for r in records
            if r.record_type == "response"
            and r.target_uri.endswith("/page")
        ]
        chunked_responses = [
            r for r in records
            if r.record_type == "response"
            and r.target_uri.endswith("/chunked")
        ]
        self.assertEqual(len(page_responses), 1)
        self.assertEqual(len(chunked_responses), 1)
        self.assertEqual(
            self.entity_of(page_responses[0]),
            self.entity_of(chunked_responses[0]),
        )
        self.assertNotEqual(
            page_responses[0].record_id, chunked_responses[0].record_id
        )
        self.assertNotEqual(
            page_responses[0].block_digest,
            chunked_responses[0].block_digest,
        )

    def test_allowed_origin_matching(self):
        origin = AllowedOrigin.parse("http://example.test:8080")
        self.assertTrue(origin.matches("http://example.test:8080/a?b=1"))
        self.assertFalse(origin.matches("http://example.test/a"))
        self.assertFalse(origin.matches("http://other.test:8080/a"))
        self.assertFalse(origin.matches("https://example.test:8080/a"))
        with self.assertRaises(ValueError):
            AllowedOrigin.parse("not-a-url")
        with self.assertRaises(ValueError):
            AllowedOrigin.parse("http://example.test/path")

    def test_warcinfo_documents_policies(self):
        records = self.archive("/page")
        warcinfo = records[0]
        self.assertEqual(warcinfo.record_type, "warcinfo")
        text = warcinfo.block.decode("latin-1")
        for token in (
            "redaction-policy",
            "content-encoding-policy",
            "http-framing-policy",
            "http-redirect-policy",
            "scope-policy",
            "allowed-origin",
        ):
            self.assertIn(token, text)
        # 后续记录都引用同一个warcinfo。
        wid = warcinfo.record_id
        for record in records[1:]:
            self.assertEqual(record.warcinfo_id, wid)


if __name__ == "__main__":
    unittest.main()
