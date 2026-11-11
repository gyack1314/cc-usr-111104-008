"""WARC 1.1帧、摘要、连续记录与截断恢复测试。"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from archive_lab.warc import (  # noqa: E402
    WarcFormatError,
    WarcTruncated,
    WarcWriter,
    build_index,
    digest_matches,
    iter_records,
    parse_one_record,
    recover_truncated_tail,
    sha256_digest,
)


class WarcFrameTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "a.warc"

    def tearDown(self):
        self.tmp.cleanup()

    def test_consecutive_records_and_digests(self):
        with WarcWriter(self.path) as writer:
            writer.write_warcinfo(b"software: test\r\n")
            rid1, _off, bd1, pd1 = writer.write_record(
                "response",
                "application/http; msgtype=response",
                b"HTTP/1.1 200 OK\r\n\r\nabc",
                target_uri="http://x/a",
                payload=b"abc",
            )
            rid2, _off, bd2, pd2 = writer.write_record(
                "response",
                "application/http; msgtype=response",
                b"HTTP/1.1 200 OK\r\n\r\ndefg",
                target_uri="http://x/b",
                payload=b"defg",
            )
        records = list(iter_records(self.path))
        self.assertEqual([r.record_type for r in records],
                         ["warcinfo", "response", "response"])
        for record in records:
            self.assertTrue(digest_matches(record.block, record.block_digest))
            self.assertTrue(record.record_id.startswith("<urn:uuid:"))
            self.assertRegex(record.date, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
            self.assertEqual(record.content_length, len(record.block))
        self.assertEqual(sha256_digest(b"abc"), pd1)
        self.assertEqual(sha256_digest(b"defg"), pd2)
        # 内容相同但地址不同仍分开保存（不做revisit压缩）。
        with WarcWriter(self.path) as writer:
            rid3, *_ = writer.write_record(
                "response", "application/http; msgtype=response",
                b"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nabc",
                target_uri="http://x/c", payload=b"abc",
            )
        self.assertNotEqual(rid3, rid1)
        entries, order = build_index(self.path)
        self.assertEqual(len(order), 4)
        self.assertEqual(entries[rid2].target_uri, "http://x/b")

    def test_base32_digest_label_shape(self):
        label = sha256_digest(b"")
        algorithm, encoded = label.split(":")
        self.assertEqual(algorithm, "sha256")
        self.assertNotIn("=", encoded)
        self.assertEqual(encoded, encoded.lower())
        self.assertTrue(digest_matches(b"", label))
        self.assertFalse(digest_matches(b"x", label))

    def test_truncation_is_not_a_record(self):
        with WarcWriter(self.path) as writer:
            writer.write_warcinfo(b"software: test\r\n")
            writer.write_record(
                "metadata", "application/json", b'{"a": 1}',
                target_uri="http://x/a",
            )
        good_size = self.path.stat().st_size
        good_records = list(iter_records(self.path))
        second_size = good_size - good_records[0].end_offset
        # 模拟写到一半崩溃：只截去不完整末尾，好记录原样保留。
        self.path.write_bytes(self.path.read_bytes()[: good_size - 11])
        kept, removed = recover_truncated_tail(self.path)
        self.assertEqual(kept, 1)
        # 恢复必须截掉整条残记录（含未写出的11字节），不能保留截断正文。
        self.assertEqual(removed, second_size - 11)
        records = list(iter_records(self.path))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].record_type, "warcinfo")

    def test_corrupt_block_digest_truncates_at_bad_record(self):
        with WarcWriter(self.path) as writer:
            writer.write_warcinfo(b"software: test\r\n")
            first = writer.write_record(
                "response", "application/http; msgtype=response",
                b"HTTP/1.1 200 OK\r\n\r\nkeep", payload=b"keep",
            )
            second = writer.write_record(
                "response", "application/http; msgtype=response",
                b"HTTP/1.1 200 OK\r\n\r\ndrop", payload=b"drop",
            )
        records = list(iter_records(self.path))
        # records[0]=warcinfo, records[1]=第一条response（好），records[2]=待损坏
        target = records[2]
        entity_offset_in_block = target.block.find(b"\r\n\r\n") + 4
        with open(self.path, "rb") as handle:
            handle.seek(target.offset)
            prefix = b""
            while not prefix.endswith(b"\r\n\r\n"):
                prefix += handle.read(1)
            block_start = handle.tell()
        flip = block_start + entity_offset_in_block + 2
        raw = bytearray(self.path.read_bytes())
        raw[flip] ^= 0x01
        self.path.write_bytes(bytes(raw))
        kept, _removed = recover_truncated_tail(self.path)
        self.assertEqual(kept, 2)  # warcinfo + 第一条好记录
        surviving = list(iter_records(self.path))
        self.assertEqual(surviving[-1].record_id, first[0])

    def test_reopen_appends_and_rebuilds_index(self):
        with WarcWriter(self.path) as writer:
            writer.write_warcinfo(b"software: test\r\n")
            writer.write_record(
                "metadata", "application/json", b"{}",
                target_uri="http://x/a",
            )
        with WarcWriter(self.path) as writer:
            self.assertEqual(writer.record_count, 2)
            writer.write_record(
                "metadata", "application/json", b'{"b": 2}',
                target_uri="http://x/b",
            )
        entries, order = build_index(self.path)
        self.assertEqual(len(order), 3)
        # 旁路索引被清空也不能掩盖文件内已有记录。
        side = Path(str(self.path) + ".idx.json")
        side.write_text('{"records": []}')
        _entries, order2 = build_index(self.path)
        self.assertEqual(len(order2), 3)
        side.unlink()
        _entries, order3 = build_index(self.path)
        self.assertEqual(len(order3), 3)

    def test_malformed_version_line(self):
        self.path.write_bytes(b"WARC/1.0\r\n")
        with self.assertRaises(WarcFormatError):
            with open(self.path, "rb") as handle:
                parse_one_record(handle)

    def test_truncated_header_raises_truncation(self):
        self.path.write_bytes(b"WARC/1.1\r\nWARC-Type: response\r\n")
        with self.assertRaises(WarcTruncated):
            with open(self.path, "rb") as handle:
                parse_one_record(handle)


if __name__ == "__main__":
    unittest.main()
