"""archive_lab命令行：采集、校验、索引重建与只读回放。

示例：
  python -m archive_lab.cli archive --config archive.json
  python -m archive_lab.cli verify out/site.warc
  python -m archive_lab.cli reindex out/site.warc
  python -m archive_lab.cli replay out/site.warc --port 8790

采集配置JSON示例：
  {
    "warc": "out/site.warc",
    "allowed_origins": ["http://127.0.0.1:8765"],
    "max_hops": 5,
    "timeout": 10,
    "urls": ["http://127.0.0.1:8765/start"]
  }
URL全部明确给定，不做任何链接发现或全站遍历。
"""
import argparse
import json
import sys
from pathlib import Path

from .archiver import Archiver
from .validator import validate_file
from .warc import build_index, recover_truncated_tail, write_index_sidecar


def _load_config(path):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    required = ("warc", "allowed_origins", "urls")
    missing = [name for name in required if not config.get(name)]
    if missing:
        raise ValueError(f"配置缺少字段: {', '.join(missing)}")
    if not isinstance(config["urls"], list) or not config["urls"]:
        raise ValueError("urls必须是非空列表")
    return config


def cmd_archive(args):
    config = _load_config(args.config)
    summary = []
    with Archiver(
        config["warc"],
        config["allowed_origins"],
        max_hops=int(config.get("max_hops", 5)),
        timeout=float(config.get("timeout", 10)),
    ) as archiver:
        for url in config["urls"]:
            chain = archiver.capture(url)
            summary.append({"seed": url, "chain": chain})
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def cmd_verify(args):
    issues, stats = validate_file(args.warc)
    payload = {
        "warc": str(args.warc),
        "stats": stats,
        "issues": [item.to_dict() for item in issues],
        "ok": not any(item.severity == "error" for item in issues),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0 if payload["ok"] else 2


def cmd_reindex(args):
    kept, removed = recover_truncated_tail(args.warc)
    entries, order = build_index(args.warc)
    write_index_sidecar(args.warc, entries, order)
    print(json.dumps(
        {
            "warc": str(args.warc),
            "records": len(order),
            "truncated_bytes_removed": removed,
            "valid_records_kept": kept,
            "sidecar": str(args.warc) + ".idx.json",
        },
        ensure_ascii=False,
        indent=2,
    ))
    return 0


def cmd_replay(args):
    from .replay import make_server

    server = make_server(args.warc, host=args.host, port=args.port)
    print(json.dumps(
        {"host": args.host, "port": server.server_port,
         "warc": str(args.warc), "records": len(server.catalog.order)},
        ensure_ascii=False,
    ), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="archive_lab",
        description="WARC 1.1网页归档器、独立校验器与只读回放",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_archive = sub.add_parser("archive", help="按配置中的明确URL采集")
    p_archive.add_argument("--config", required=True)
    p_archive.set_defaults(func=cmd_archive)

    p_verify = sub.add_parser("verify", help="独立校验WARC文件")
    p_verify.add_argument("warc")
    p_verify.set_defaults(func=cmd_verify)

    p_reindex = sub.add_parser("reindex", help="从WARC文件重建索引缓存")
    p_reindex.add_argument("warc")
    p_reindex.set_defaults(func=cmd_reindex)

    p_replay = sub.add_parser("replay", help="环回只读HTTP回放服务")
    p_replay.add_argument("warc")
    p_replay.add_argument("--host", default="127.0.0.1")
    p_replay.add_argument("--port", type=int, default=0)
    p_replay.set_defaults(func=cmd_replay)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
