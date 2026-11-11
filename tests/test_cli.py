"""CLI子进程测试：用-I隔离解释器，仓库路径与输出目录均以参数传入。"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from source_lab.http import start  # noqa: E402


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start(ROOT / "sources" / "normal.json")
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        cls.tmp = tempfile.TemporaryDirectory()
        cls.work = Path(cls.tmp.name)
        cls.runner = cls.work / "run_cli.py"
        # 引导脚本只通过argv接收仓库路径，避免依赖当前工作目录或PYTHONPATH。
        cls.runner.write_text(
            "import sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from archive_lab.cli import main\n"
            "raise SystemExit(main(sys.argv[2:]))\n"
        )
        cls.warc = cls.work / "cli.warc"
        cls.config = cls.work / "config.json"
        cls.config.write_text(json.dumps({
            "warc": str(cls.warc),
            "allowed_origins": [cls.origin],
            "max_hops": 5,
            "timeout": 5,
            "urls": [
                cls.origin + "/entry",
                cls.origin + "/gzip",
                cls.origin + "/outside",
            ],
        }))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-I", str(self.runner), str(ROOT), *args],
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_archive_verify_reindex_and_exit_codes(self):
        result = self.run_cli("archive", "--config", str(self.config))
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(len(summary), 3)
        self.assertTrue(self.warc.exists())
        self.assertTrue(Path(str(self.warc) + ".idx.json").exists())

        result = self.run_cli("verify", str(self.warc))
        self.assertEqual(result.returncode, 0, result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["stats"]["by_type"]["warcinfo"], 1)

        result = self.run_cli("reindex", str(self.warc))
        self.assertEqual(result.returncode, 0, result.stderr)
        rebuilt = json.loads(result.stdout)
        self.assertEqual(rebuilt["records"], report["stats"]["records"])

    def test_verify_returns_nonzero_on_truncation(self):
        result = self.run_cli("archive", "--config", str(self.config))
        self.assertEqual(result.returncode, 0)
        raw = self.warc.read_bytes()
        self.warc.write_bytes(raw[: len(raw) - 23])
        result = self.run_cli("verify", str(self.warc))
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["ok"])
        self.assertTrue(
            any(item["code"] == "truncated-record"
                for item in report["issues"])
        )

    def test_reindex_recovers_truncated_tail(self):
        self.run_cli("archive", "--config", str(self.config))
        full_size = self.warc.stat().st_size
        truncated_size = full_size - 40
        self.warc.write_bytes(self.warc.read_bytes()[:truncated_size])
        result = self.run_cli("reindex", str(self.warc))
        self.assertEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        # 恢复从截断文件截去整条残记录，移除量 >= 切掉的40字节。
        self.assertGreaterEqual(report["truncated_bytes_removed"], 40)
        self.assertGreater(report["valid_records_kept"], 0)
        self.assertEqual(
            self.warc.stat().st_size,
            truncated_size - report["truncated_bytes_removed"],
        )
        # 恢复后校验通过。
        verify = self.run_cli("verify", str(self.warc))
        self.assertEqual(verify.returncode, 0)


if __name__ == "__main__":
    unittest.main()
