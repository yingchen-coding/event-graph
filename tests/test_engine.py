from event_graph.engine import (
    add_edge,
    add_note,
    append_events,
    connect,
    convert_agent_trace_jsonl,
    convert_macos_log_json,
    generate_file_events,
    generate_synthetic_events,
    ingest_adapter_events,
    ingest_configured_events,
    ingest_events,
    ingest_partitioned_events,
    load_sample,
    malware_hits,
    related_events,
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
