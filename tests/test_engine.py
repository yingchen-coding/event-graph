from event_graph.engine import (
    add_edge,
    add_note,
    connect,
    generate_synthetic_events,
    ingest_events,
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
