"""独立校验器测试：坏摘要、错长度、帧损坏、禁用头、悬空引用均可定位。"""
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from archive_lab.archiver import Archiver  # noqa: E402
from archive_lab.validator import validate_file  # noqa: E402
from archive_lab.warc import iter_records  # noqa: E402
from source_lab.http import start  # noqa: E402


class ValidatorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start(
            Path(__file__).resolve().parents[1] / "sources" / "normal.json"
        )
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.warc = Path(self.tmp.name) / "v.warc"
        with Archiver(self.warc, [self.origin]) as archiver:
            archiver.capture(self.origin + "/page")
            archiver.capture(self.origin + "/gzip")

    def tearDown(self):
        self.tmp.cleanup()

    def _flip_entity_byte(self, target):
        entity_offset_in_block = target.block.find(b"\r\n\r\n") + 4
        with open(self.warc, "rb") as handle:
            handle.seek(target.offset)
            prefix = b""
            while not prefix.endswith(b"\r\n\r\n"):
                prefix += handle.read(1)
            block_start = handle.tell()
        raw = bytearray(self.warc.read_bytes())
        raw[block_start + entity_offset_in_block + 2] ^= 0x01
        self.warc.write_bytes(bytes(raw))

    def test_clean_archive_passes(self):
        issues, stats = validate_file(self.warc)
        self.assertEqual([i.to_dict() for i in issues], [])
        self.assertGreaterEqual(stats["records"], 7)
        self.assertEqual(stats["by_type"]["warcinfo"], 1)

    def test_bad_block_and_payload_digest_located(self):
        target = [r for r in iter_records(self.warc)
                  if r.record_type == "response"][0]
        self._flip_entity_byte(target)
        issues, _stats = validate_file(self.warc)
        block_issues = [i for i in issues if i.code == "bad-block-digest"]
        payload_issues = [i for i in issues if i.code == "bad-payload-digest"]
        self.assertEqual(len(block_issues), 1)
        self.assertEqual(block_issues[0].record_id, target.record_id)
        self.assertEqual(block_issues[0].offset, target.offset)
        self.assertEqual(payload_issues[0].record_id, target.record_id)

    def test_truncated_tail_reported_as_error(self):
        raw = self.warc.read_bytes()
        self.warc.write_bytes(raw[: len(raw) - 31])
        issues, _stats = validate_file(self.warc)
        self.assertTrue(
            any(i.code == "truncated-record" and i.severity == "error"
                for i in issues)
        )

    def test_warc_content_length_mismatch_detected(self):
        raw = self.warc.read_bytes()
        match = re.search(rb"Content-Length: (\d+)\r\n\r\n", raw)
        tampered = (
            raw[: match.start(1)] + b"9" + raw[match.end(1):]
        )
        self.warc.write_bytes(tampered)
        issues, _stats = validate_file(self.warc)
        self.assertTrue(any(i.severity == "error" for i in issues))
        self.assertTrue(
            any(i.code in (
                "malformed-frame", "truncated-record", "bad-content-length",
            ) for i in issues)
        )

    def test_forbidden_headers_flagged(self):
        # 手工植入一个含Set-Cookie的响应块，校验器必须报禁用头。
        records = list(iter_records(self.warc))
        target = [r for r in records if r.record_type == "response"][0]
        poisoned_block = target.block.replace(
            b"Content-Length:", b"Set-Cookie: x=y\r\nContent-Length:", 1
        )
        # 重写文件：保留target之前的字节，替换块后按新长度重拼整条记录。
        before = self.warc.read_bytes()[: target.offset]
        head, sep, tail = target.block.partition(b"\r\n\r\n")
        new_block = head + b"\r\nSet-Cookie: x=y" + sep + tail
        # 直接构造最小WARC记录替换（摘要故意不更新，应同时报坏摘要/禁用头）。
        from archive_lab.warc import RECORD_TERMINATOR

        lines = [b"WARC/1.1\r\n"]
        for key, value in target.headers:
            if key == "Content-Length":
                value = str(len(new_block))
            lines.append(f"{key}: {value}\r\n".encode("latin-1"))
        lines.append(b"\r\n")
        rebuilt = b"".join(lines) + new_block + RECORD_TERMINATOR
        self.warc.write_bytes(before + rebuilt)
        issues, _stats = validate_file(self.warc)
        self.assertTrue(any(i.code == "forbidden-header" for i in issues))

    def test_dangling_reference_detected(self):
        records = list(iter_records(self.warc))
        target = [r for r in records
                  if r.record_type == "metadata" and r.concurrent_to][0]
        raw = self.warc.read_bytes()
        fake = "<urn:uuid:deadbeef-0000-0000-0000-000000000000>"
        marker = f"WARC-Concurrent-To: {target.concurrent_to}".encode()
        replacement = f"WARC-Concurrent-To: {fake}".encode()
        self.assertIn(marker, raw)
        self.warc.write_bytes(raw.replace(marker, replacement, 1))
        issues, _stats = validate_file(self.warc)
        self.assertTrue(
            any(i.code == "dangling-reference"
                and i.record_id == target.record_id for i in issues)
        )

    def test_duplicate_record_id_detected(self):
        records = list(iter_records(self.warc))
        first_id_line = f"WARC-Record-ID: {records[0].record_id}\r\n".encode()
        target = records[1]
        target_id_line = f"WARC-Record-ID: {target.record_id}\r\n".encode()
        raw = self.warc.read_bytes()
        self.warc.write_bytes(raw.replace(target_id_line, first_id_line, 1))
        issues, _stats = validate_file(self.warc)
        self.assertTrue(
            any(i.code == "duplicate-record-id"
                and i.record_id == records[0].record_id for i in issues)
        )

    def test_bad_date_and_id_format(self):
        records = list(iter_records(self.warc))
        target = records[1]
        raw = self.warc.read_bytes()
        old_date = f"WARC-Date: {target.date}\r\n".encode()
        raw = raw.replace(old_date, b"WARC-Date: 2026-13-99T99:99:99Z\r\n", 1)
        old_id = f"WARC-Record-ID: {target.record_id}\r\n".encode()
        raw = raw.replace(old_id, b"WARC-Record-ID: <not-a-uuid>\r\n", 1)
        self.warc.write_bytes(raw)
        issues, _stats = validate_file(self.warc)
        codes = {i.code for i in issues}
        self.assertIn("bad-date", codes)
        self.assertIn("bad-record-id", codes)


if __name__ == "__main__":
    unittest.main()
