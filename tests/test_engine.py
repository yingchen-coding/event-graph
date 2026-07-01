from event_graph.cli import _emit_json, _truncate_details
from event_graph.engine import (
    add_edge,
    add_note,
    append_events,
    append_logs,
    connect,
    convert_agent_trace_jsonl,
    convert_macos_log_json,
    explain_subgraph,
    generate_file_events,
    generate_synthetic_events,
    ingest_adapter_events,
    ingest_configured_events,
    ingest_events,
    ingest_partitioned_events,
    load_sample,
    malware_hits,
    neighborhood,
    related_events,
    remove_edge,
    search_graph,
)


def test_malware_hits_include_category_and_intel_matches():
    conn = connect()
    load_sample(conn)
    hits = malware_hits(conn)
    reasons = {item["match_reason"] for item in hits}
    assert "category" in reasons
    assert "intel-ip" in reasons


def test_related_events_walks_from_user_to_logs():
    conn = connect()
    load_sample(conn)
    events = related_events(conn, "user:alice", hops=3)
    joined = "\n".join(str(item) for item in events)
    assert "10.0.0.5" in joined
    assert "bad.example" in joined
    assert "Malware callback" in joined


def test_manual_edge_and_note_are_searchable():
    conn = connect()
    load_sample(conn)
    add_edge(conn, "user:alice", "threat:ExampleRAT", "suspected_compromise")
    note = add_note(conn, "user:alice", "Seen in incident INC-123")
    assert note["id"]
    results = search_graph(conn, "INC-123")
    assert results[0]["item"] == "user:alice"


def test_removed_manual_edge_can_be_readded():
    conn = connect()
    load_sample(conn)
    add_edge(conn, "user:alice", "ticket:INC-123", "owns")
    remove_edge(conn, "user:alice", "ticket:INC-123", "owns")
    assert "ticket:INC-123" not in str(neighborhood(conn, "user:alice", hops=1, limit=50))
    add_edge(conn, "user:alice", "ticket:INC-123", "owns")
    assert "ticket:INC-123" in str(neighborhood(conn, "user:alice", hops=1, limit=50))


def test_related_events_walks_reverse_edges():
    conn = connect()
    load_sample(conn)
    events = related_events(conn, "domain:bad.example", hops=3, limit=20)
    joined = "\n".join(str(item) for item in events)
    assert "user:alice" in joined
    assert "Malware callback" in joined


def test_explain_subgraph_returns_edges_and_event_evidence():
    conn = connect()
    load_sample(conn)
    explanation = explain_subgraph(conn, "domain:bad.example", hops=2, limit=20)

    assert explanation["seed"] == "domain:bad.example"
    assert explanation["nodes"]
    assert explanation["edges"]
    assert explanation["events"]
    assert "Malware callback" in str(explanation["events"])
    assert any(edge["dst"] == "domain:bad.example" for edge in explanation["edges"])


def test_walk_does_not_confuse_prefix_entities(tmp_path):
    path = tmp_path / "events.csv"
    path.write_text(
        "\n".join(
            [
                "ts,src,dst,rel,details",
                "2026-01-01T00:00:00Z,user:alice,user:a,delegated,prefix edge",
                "2026-01-01T00:00:01Z,user:a,ticket:INC-1,opened,target ticket",
                "",
            ]
        ),
        encoding="utf-8",
    )
    conn = connect()
    ingest_events(conn, path)

    nodes = neighborhood(conn, "user:alice", hops=2, limit=10)
    assert "user:a" in {item["node"] for item in nodes}
    events = related_events(conn, "user:alice", hops=2, limit=10)
    assert "target ticket" in str(events)


def test_generic_events_can_be_indexed(tmp_path):
    path = tmp_path / "events.csv"
    generate_synthetic_events(path, 100)
    conn = connect()
    result = ingest_events(conn, path)
    assert result["events"] == 100
    events = related_events(conn, "user:alice", hops=2, limit=10)
    assert events
    assert "user:alice" in str(events)


def test_generic_events_can_be_appended_incrementally(tmp_path):
    first = tmp_path / "events1.csv"
    second = tmp_path / "events2.csv"
    generate_synthetic_events(first, 10)
    second.write_text(
        "\n".join(
            [
                "ts,src,dst,rel,details",
                "2026-01-01T00:00:00Z,user:alice,ticket:INC-999,opened,late ticket",
                "2026-01-01T00:00:01Z,ticket:INC-999,service:export,touched,late export",
                "",
            ]
        ),
        encoding="utf-8",
    )
    conn = connect()
    ingest_events(conn, first)
    result = append_events(conn, second)
    assert result["events"] == 12
    assert result["appended_events"] == 2
    events = related_events(conn, "ticket:INC-999", hops=2, limit=10)
    joined = "\n".join(str(item) for item in events)
    assert "late ticket" in joined
    assert "late export" in joined


def test_security_logs_append_can_initialize_empty_database(tmp_path):
    path = tmp_path / "firewall.csv"
    path.write_text(
        "\n".join(
            [
                "ts,src_ip,dst_ip,src_user,url_domain,threat_name,threat_category,action,application,bytes",
                "2026-01-01T00:00:00Z,10.0.0.5,203.0.113.9,alice,bad.example,"
                "Malware callback,malware,allow,dns,512",
                "",
            ]
        ),
        encoding="utf-8",
    )
    conn = connect()
    assert append_logs(conn, path) == 1
    events = related_events(conn, "domain:bad.example", hops=2, limit=10)
    assert "Malware callback" in str(events)


def test_configured_ingest_maps_arbitrary_columns(tmp_path):
    source = tmp_path / "activity.csv"
    config = tmp_path / "mapping.json"
    source.write_text(
        "\n".join(
            [
                "time,actor,verb,target,message",
                "2026-01-01T00:00:00Z,alice,opened,ticket-1,needs review",
                "2026-01-01T00:00:01Z,bob,closed,ticket-1,done",
                "",
            ]
        ),
        encoding="utf-8",
    )
    config.write_text(
        """
        {
          "timestamp": "{time}",
          "details": "{message}",
          "edges": [
            {"src": "user:{actor}", "rel": "{verb}", "dst": "ticket:{target}"}
          ]
        }
        """,
        encoding="utf-8",
    )
    conn = connect()
    result = ingest_configured_events(conn, source, config)
    assert result["events"] == 2
    events = related_events(conn, "ticket:ticket-1", hops=1, limit=10)
    joined = "\n".join(str(item) for item in events)
    assert "needs review" in joined
    assert "done" in joined


def test_local_file_events_can_be_ingested(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("hello", encoding="utf-8")
    output = tmp_path / "files.csv"
    generated = generate_file_events(root, output)
    assert generated["files"] == 1
    assert generated["events"] == 2
    conn = connect()
    ingest_events(conn, output)
    events = related_events(conn, f"dir:{root}", hops=1, limit=10)
    assert "a.txt" in str(events)


def test_macos_log_json_can_be_converted_and_ingested(tmp_path):
    raw = tmp_path / "macos.json"
    output = tmp_path / "macos.csv"
    raw.write_text(
        """
        [
          {
            "timestamp": "2026-01-01 00:00:00.000000-0800",
            "process": "backupd",
            "subsystem": "com.apple.TimeMachine",
            "category": "backup",
            "eventMessage": "Backup started",
            "messageType": "Info"
          }
        ]
        """,
        encoding="utf-8",
    )
    converted = convert_macos_log_json(raw, output)
    assert converted["events"] == 1
    conn = connect()
    ingest_events(conn, output)
    events = related_events(conn, "process:backupd", hops=1, limit=10)
    assert "Backup started" in str(events)


def test_builtin_adapters_cover_product_audit_and_tickets(tmp_path):
    product = tmp_path / "product.csv"
    audit = tmp_path / "audit.csv"
    tickets = tmp_path / "tickets.csv"
    product.write_text(
        "ts,user_id,session_id,event_name,object_id,properties\n"
        "2026-01-01T00:00:00Z,alice,s1,export_failed,report-1,timeout\n",
        encoding="utf-8",
    )
    audit.write_text(
        "ts,actor,action,resource,ip,details\n"
        "2026-01-01T00:00:00Z,alice,deleted,file-1,10.0.0.5,cleanup\n",
        encoding="utf-8",
    )
    tickets.write_text(
        "ts,ticket_id,reporter,assignee,status,summary\n"
        "2026-01-01T00:00:00Z,INC-1,alice,bob,open,export failed\n",
        encoding="utf-8",
    )

    conn = connect()
    assert ingest_adapter_events(conn, product, "product")["events"] == 3
    assert "export_failed" in str(related_events(conn, "user:alice", hops=1, limit=10))

    conn = connect()
    assert ingest_adapter_events(conn, audit, "audit")["events"] == 2
    assert "file-1" in str(related_events(conn, "actor:alice", hops=1, limit=10))

    conn = connect()
    assert ingest_adapter_events(conn, tickets, "ticket")["events"] == 3
    assert "export failed" in str(related_events(conn, "ticket:INC-1", hops=1, limit=10))


def test_agent_trace_jsonl_can_be_converted_and_ingested(tmp_path):
    raw = tmp_path / "trace.jsonl"
    output = tmp_path / "trace.csv"
    raw.write_text(
        "\n".join(
            [
                '{"type":"user","sessionId":"s1","timestamp":"2026-01-01T00:00:00Z",'
                '"cwd":"/repo","message":{"role":"user","content":"please run tests"}}',
                '{"type":"assistant","sessionId":"s1","timestamp":"2026-01-01T00:00:01Z",'
                '"message":{"role":"assistant","model":"m","content":[{"type":"text","text":"ok"},'
                '{"type":"tool_use","name":"pytest"}]}}',
            ]
        ),
        encoding="utf-8",
    )
    converted = convert_agent_trace_jsonl(raw, output)
    assert converted["events"] == 4
    assert converted["sessions"] == ["s1"]
    conn = connect()
    ingest_events(conn, output)
    assert "pytest" in str(related_events(conn, "session:s1", hops=1, limit=10))


def test_partitioned_parquet_ingest_filters_before_indexing(tmp_path):
    csv_path = tmp_path / "events.csv"
    parquet_dir = tmp_path / "events_parquet"
    csv_path.write_text(
        "\n".join(
            [
                "ts,src,dst,rel,day,details",
                "2026-01-01T00:00:00Z,user:alice,service:billing,used,2026-01-01,keep",
                "2026-01-02T00:00:00Z,user:bob,service:search,used,2026-01-02,drop",
                "",
            ]
        ),
        encoding="utf-8",
    )
    conn = connect()
    conn.execute(
        f"""
        COPY (
          SELECT * FROM read_csv_auto('{csv_path}', header=true)
        )
        TO '{parquet_dir}' (FORMAT parquet, PARTITION_BY (day))
        """
    )
    conn = connect()
    result = ingest_partitioned_events(conn, parquet_dir, where="day = DATE '2026-01-01'")
    assert result["events"] == 1
    assert "keep" in str(related_events(conn, "user:alice", hops=1, limit=10))
    assert not related_events(conn, "user:bob", hops=1, limit=10)


def test_partitioned_parquet_where_rejects_statement_injection(tmp_path):
    csv_path = tmp_path / "events.csv"
    parquet_dir = tmp_path / "events_parquet"
    csv_path.write_text(
        "ts,src,dst,rel,day,details\n"
        "2026-01-01T00:00:00Z,user:alice,service:billing,used,2026-01-01,keep\n",
        encoding="utf-8",
    )
    conn = connect()
    conn.execute(
        f"""
        COPY (
          SELECT * FROM read_csv_auto('{csv_path}', header=true)
        )
        TO '{parquet_dir}' (FORMAT parquet, PARTITION_BY (day))
        """
    )
    conn = connect()
    try:
        ingest_partitioned_events(conn, parquet_dir, where="true; DROP TABLE events")
    except ValueError as error:
        assert "read-only filter" in str(error)
    else:
        raise AssertionError("unsafe where clause should fail")


def test_cli_truncates_long_details_by_default_shape():
    rows = [{"details": "x" * 20, "event_id": 1}]
    truncated = _truncate_details(rows, 8)
    assert truncated[0]["details"] == "x" * 8 + "... [truncated 12 chars]"
    assert rows[0]["details"] == "x" * 20
    assert _truncate_details(rows, 0)[0]["details"] == "x" * 20


def test_cli_can_write_json_artifact(tmp_path):
    output = tmp_path / "nested" / "result.json"
    _emit_json({"rows": 10, "query_millis": 1.5}, output)
    assert '"rows": 10' in output.read_text(encoding="utf-8")


def test_iter_json_records_handles_all_shapes(tmp_path):
    import json as _json

    from event_graph.engine import _iter_json_records
    cases = {
        "array.json": (_json.dumps([{"a": 1}, {"b": 2}, "skip", {"c": 3}]), 3),
        "single.json": (_json.dumps({"a": 1}), 1),
        "lines.jsonl": ('{"a":1}\n{"b":2}\n\n{"c":3}\n', 3),
        "garbage_line.jsonl": ('{"a":1}\nNOT JSON\n{"b":2}\n', 2),
        "pretty_obj.json": ('{\n  "a": 1,\n  "b": [1,2]\n}\n', 1),
        "pretty_arr.json": ('[\n  {"a":1},\n  {"b":2}\n]\n', 2),
        "empty.json": ("", 0),
        "ws.json": ("   \n\n  ", 0),
        "garbage.txt": ("not json\nreally not", 0),
    }
    for name, (content, expect) in cases.items():
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        assert len(list(_iter_json_records(p))) == expect, name


def test_iter_json_records_streams_jsonl_without_loading_whole_file(tmp_path, monkeypatch):
    # Regression: the parser used to read_text() the entire file before yielding a record, so a
    # multi-GB trace would OOM and `limit=` couldn't bound memory. For line-delimited input it must
    # now stream from the handle — proven here by banning the whole-file read_text().
    from pathlib import Path

    from event_graph import engine

    big = tmp_path / "trace.jsonl"
    with big.open("w", encoding="utf-8") as fh:
        for _ in range(5000):
            fh.write('{"sessionId":"s","timestamp":"t","message":{"role":"user","content":"hi"}}\n')

    original = Path.read_text
    def _banned(self, *a, **k):
        if self == big:
            raise AssertionError("JSONL must be streamed, not read whole into memory")
        return original(self, *a, **k)
    monkeypatch.setattr(Path, "read_text", _banned)

    out = tmp_path / "events.csv"
    result = engine.convert_agent_trace_jsonl(big, out, limit=100)
    assert result["events"] <= 100  # limit actually bounds work now
