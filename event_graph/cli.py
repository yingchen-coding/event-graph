from __future__ import annotations

import argparse
import json
from pathlib import Path

from .engine import (
    add_edge,
    add_note,
    append_logs,
    benchmark,
    benchmark_events,
    connect,
    export_graph,
    generate_synthetic_events,
    generate_synthetic_logs,
    ingest_events,
    ingest_sources,
    load_sample,
    malware_hits,
    neighborhood,
    related_events,
    remove_edge,
    remove_note,
    search_graph,
)


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, default=str))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Find related events quickly with entity-edge indexes."
    )
    parser.add_argument("--db", default=":memory:", help="DuckDB path, or :memory:")
    sub = parser.add_subparsers(dest="command", required=True)

    sample = sub.add_parser("load-sample", help="load bundled sample data into the database")
    sample.set_defaults(func="load_sample")

    ingest = sub.add_parser("ingest", help="ingest generic event edges and materialize indexes")
    ingest.add_argument("--events", type=Path, required=True)
    ingest.set_defaults(func="ingest")

    ingest_sec = sub.add_parser(
        "ingest-security",
        help="ingest security logs with firewall mapping",
    )
    ingest_sec.add_argument("--logs", type=Path, required=True)
    ingest_sec.add_argument("--threat-intel", type=Path)
    ingest_sec.set_defaults(func="ingest_security")

    append = sub.add_parser("append", help="append logs and rebuild entity indexes")
    append.add_argument("--logs", type=Path, required=True)
    append.set_defaults(func="append")

    scan = sub.add_parser("malware-hits", help="security adapter: find malware-related events")
    scan.add_argument("--limit", type=int, default=50)
    scan.set_defaults(func="malware_hits")

    events = sub.add_parser("related-events", help="find all events related to a seed entity")
    events.add_argument("seed", help="node id such as ip:10.0.0.5 or user:alice")
    events.add_argument("--hops", type=int, default=2)
    events.add_argument("--limit", type=int, default=100)
    events.set_defaults(func="related_events")

    hood = sub.add_parser("neighborhood", help="walk graph edges from a seed node")
    hood.add_argument("seed")
    hood.add_argument("--hops", type=int, default=3)
    hood.add_argument("--limit", type=int, default=100)
    hood.set_defaults(func="neighborhood")

    add_rel = sub.add_parser("add-edge", help="add a manual relationship overlay")
    add_rel.add_argument("src")
    add_rel.add_argument("rel")
    add_rel.add_argument("dst")
    add_rel.add_argument("--note", default="")
    add_rel.set_defaults(func="add_edge")

    del_rel = sub.add_parser("remove-edge", help="delete/suppress a relationship with tombstone")
    del_rel.add_argument("src")
    del_rel.add_argument("rel")
    del_rel.add_argument("dst")
    del_rel.add_argument("--reason", default="")
    del_rel.set_defaults(func="remove_edge")

    note = sub.add_parser("add-note", help="add analyst note to an entity")
    note.add_argument("node")
    note.add_argument("note")
    note.add_argument("--source", default="manual")
    note.set_defaults(func="add_note")

    del_note = sub.add_parser("remove-note", help="delete an analyst note")
    del_note.add_argument("note_id")
    del_note.set_defaults(func="remove_note")

    search = sub.add_parser("search", help="search entity ids and active notes")
    search.add_argument("query")
    search.add_argument("--limit", type=int, default=50)
    search.set_defaults(func="search")

    export = sub.add_parser("export", help="export to kuzu-csv or memgraph-cypher")
    export.add_argument("format", choices=("kuzu-csv", "memgraph-cypher"))
    export.add_argument("output_dir", type=Path)
    export.set_defaults(func="export")

    synthetic = sub.add_parser("generate-synthetic-security", help="write synthetic security CSV")
    synthetic.add_argument("path", type=Path)
    synthetic.add_argument("--rows", type=int, default=100_000)
    synthetic.set_defaults(func="generate_synthetic_security")

    synthetic_events = sub.add_parser("generate-synthetic", help="write generic event-edge CSV")
    synthetic_events.add_argument("path", type=Path)
    synthetic_events.add_argument("--rows", type=int, default=100_000)
    synthetic_events.set_defaults(func="generate_synthetic")

    bench = sub.add_parser("benchmark", help="benchmark generic ingest and related-event lookup")
    bench.add_argument("--csv", type=Path, default=Path("/tmp/event_graph_benchmark.csv"))
    bench.add_argument("--rows", type=int, default=100_000)
    bench.add_argument("--seed", default="domain:bad.example")
    bench.add_argument("--hops", type=int, default=2)
    bench.add_argument("--limit", type=int, default=100)
    bench.set_defaults(func="benchmark")

    bench_sec = sub.add_parser("benchmark-security", help="benchmark security adapter")
    bench_sec.add_argument(
        "--csv",
        type=Path,
        default=Path("/tmp/event_graph_security_benchmark.csv"),
    )
    bench_sec.add_argument("--rows", type=int, default=100_000)
    bench_sec.add_argument("--seed", default="domain:bad.example")
    bench_sec.add_argument("--hops", type=int, default=2)
    bench_sec.add_argument("--limit", type=int, default=100)
    bench_sec.set_defaults(func="benchmark_security")

    args = parser.parse_args(argv)
    conn = connect(args.db)

    if args.func == "load_sample":
        load_sample(conn)
        print(f"sample loaded into {args.db}")
    elif args.func == "ingest":
        _print_json(ingest_events(conn, args.events))
    elif args.func == "ingest_security":
        _print_json(ingest_sources(conn, args.logs, args.threat_intel))
    elif args.func == "append":
        _print_json({"logs": append_logs(conn, args.logs)})
    elif args.func == "malware_hits":
        _print_json(malware_hits(conn, args.limit))
    elif args.func == "related_events":
        _print_json(related_events(conn, args.seed, args.hops, args.limit))
    elif args.func == "neighborhood":
        _print_json(neighborhood(conn, args.seed, args.hops, args.limit))
    elif args.func == "add_edge":
        _print_json(add_edge(conn, args.src, args.dst, args.rel, note=args.note))
    elif args.func == "remove_edge":
        remove_edge(conn, args.src, args.dst, args.rel, reason=args.reason)
        _print_json({"removed": True})
    elif args.func == "add_note":
        _print_json(add_note(conn, args.node, args.note, source=args.source))
    elif args.func == "remove_note":
        remove_note(conn, args.note_id)
        _print_json({"removed": True})
    elif args.func == "search":
        _print_json(search_graph(conn, args.query, args.limit))
    elif args.func == "export":
        _print_json(export_graph(conn, args.output_dir, args.format))
    elif args.func == "generate_synthetic_security":
        generate_synthetic_logs(args.path, args.rows)
        _print_json({"path": str(args.path), "rows": args.rows})
    elif args.func == "benchmark":
        _print_json(benchmark_events(conn, args.csv, args.rows, args.seed, args.hops, args.limit))
    elif args.func == "benchmark_security":
        _print_json(benchmark(conn, args.csv, args.rows, args.seed, args.hops, args.limit))
    elif args.func == "generate_synthetic":
        generate_synthetic_events(args.path, args.rows)
        _print_json({"path": str(args.path), "rows": args.rows})
    else:
        raise AssertionError(args.func)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
