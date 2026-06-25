from __future__ import annotations

import csv
import json
import time
import uuid
from pathlib import Path
from typing import Any

import duckdb

REQUIRED_LOG_COLUMNS = {
    "ts",
    "src_ip",
    "dst_ip",
    "src_user",
    "url_domain",
    "threat_name",
    "threat_category",
    "action",
    "application",
    "bytes",
}
LOG_COLUMNS = [
    "ts",
    "src_ip",
    "dst_ip",
    "src_user",
    "url_domain",
    "threat_name",
    "threat_category",
    "action",
    "application",
    "bytes",
]


def connect(database: str | Path = ":memory:") -> duckdb.DuckDBPyConnection:
    return duckdb.connect(str(database))


def _reader_sql(path: str | Path) -> str:
    source = str(path)
    escaped = source.replace("'", "''")
    suffix = Path(source).suffix.lower()
    if suffix == ".parquet":
        return f"read_parquet('{escaped}')"
    if suffix in {".csv", ".tsv"}:
        return f"read_csv_auto('{escaped}', header=true)"
    if suffix in {".json", ".jsonl", ".ndjson"}:
        return f"read_json_auto('{escaped}')"
    raise ValueError(f"unsupported source format: {source}")


def register_sources(
    conn: duckdb.DuckDBPyConnection,
    logs: str | Path,
    threat_intel: str | Path | None = None,
) -> None:
    conn.execute(f"CREATE OR REPLACE VIEW firewall_logs AS SELECT * FROM {_reader_sql(logs)}")
    columns = {row[1] for row in conn.execute("PRAGMA table_info('firewall_logs')").fetchall()}
    missing = sorted(REQUIRED_LOG_COLUMNS - columns)
    if missing:
        raise ValueError(f"firewall log source is missing columns: {', '.join(missing)}")

    if threat_intel:
        conn.execute(
            f"CREATE OR REPLACE VIEW threat_intel AS SELECT * FROM {_reader_sql(threat_intel)}"
        )
    else:
        conn.execute(
            """
            CREATE OR REPLACE VIEW threat_intel AS
            SELECT
              NULL::VARCHAR AS indicator_type,
              NULL::VARCHAR AS indicator_value,
              NULL::VARCHAR AS malware_family,
              NULL::VARCHAR AS severity
            WHERE false
            """
        )
    create_graph_views(conn)


def load_sample(conn: duckdb.DuckDBPyConnection) -> None:
    root = Path(__file__).resolve().parents[1] / "examples"
    log_reader = _reader_sql(root / "firewall_logs.csv")
    intel_reader = _reader_sql(root / "threat_intel.csv")
    conn.execute(
        f"""
        CREATE OR REPLACE TABLE firewall_logs AS
        SELECT row_number() OVER () AS event_id, *
        FROM {log_reader}
        """
    )
    conn.execute(f"CREATE OR REPLACE TABLE threat_intel AS SELECT * FROM {intel_reader}")
    create_graph_views(conn)
    materialize_entity_edges(conn)
    materialize_entity_events(conn)


def ingest_sources(
    conn: duckdb.DuckDBPyConnection,
    logs: str | Path,
    threat_intel: str | Path | None = None,
    *,
    materialize: bool = True,
) -> dict[str, int]:
    conn.execute(
        f"""
        CREATE OR REPLACE TABLE firewall_logs AS
        SELECT row_number() OVER () AS event_id, *
        FROM {_reader_sql(logs)}
        """
    )
    if threat_intel:
        reader = _reader_sql(threat_intel)
        conn.execute(f"CREATE OR REPLACE TABLE threat_intel AS SELECT * FROM {reader}")
    else:
        conn.execute(
            """
            CREATE OR REPLACE TABLE threat_intel AS
            SELECT
              NULL::VARCHAR AS indicator_type,
              NULL::VARCHAR AS indicator_value,
              NULL::VARCHAR AS malware_family,
              NULL::VARCHAR AS severity
            WHERE false
            """
        )
    create_graph_views(conn)
    if materialize:
        materialize_entity_edges(conn)
        materialize_entity_events(conn)
    return {
        "logs": conn.execute("SELECT count(*) FROM firewall_logs").fetchone()[0],
        "entity_edges": _relation_count(conn, "entity_edges"),
        "entity_events": _relation_count(conn, "entity_events"),
    }


def append_logs(conn: duckdb.DuckDBPyConnection, logs: str | Path) -> int:
    offset = conn.execute("SELECT COALESCE(max(event_id), 0) FROM firewall_logs").fetchone()[0]
    conn.execute(
        f"""
        INSERT INTO firewall_logs
        SELECT {offset} + row_number() OVER () AS event_id, *
        FROM {_reader_sql(logs)}
        """
    )
    create_graph_views(conn)
    materialize_entity_edges(conn)
    materialize_entity_events(conn)
    return conn.execute("SELECT count(*) FROM firewall_logs").fetchone()[0]


def create_graph_views(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute(
        """
        CREATE OR REPLACE VIEW graph_edges AS
        SELECT DISTINCT
          'ip:' || src_ip AS src,
          'ip:' || dst_ip AS dst,
          'network_flow' AS rel,
          ts,
          action,
          application,
          threat_name,
          threat_category
        FROM firewall_logs
        WHERE src_ip IS NOT NULL AND dst_ip IS NOT NULL

        UNION ALL
        SELECT DISTINCT
          'user:' || src_user AS src,
          'ip:' || src_ip AS dst,
          'used_source_ip' AS rel,
          ts,
          action,
          application,
          threat_name,
          threat_category
        FROM firewall_logs
        WHERE src_user IS NOT NULL AND src_user != '' AND src_ip IS NOT NULL

        UNION ALL
        SELECT DISTINCT
          'ip:' || dst_ip AS src,
          'domain:' || url_domain AS dst,
          'contacted_domain' AS rel,
          ts,
          action,
          application,
          threat_name,
          threat_category
        FROM firewall_logs
        WHERE url_domain IS NOT NULL AND url_domain != '' AND dst_ip IS NOT NULL

        UNION ALL
        SELECT DISTINCT
          'ip:' || dst_ip AS src,
          'threat:' || COALESCE(NULLIF(threat_name, ''), threat_category) AS dst,
          'triggered_threat' AS rel,
          ts,
          action,
          application,
          threat_name,
          threat_category
        FROM firewall_logs
        WHERE dst_ip IS NOT NULL
          AND (threat_name IS NOT NULL OR threat_category IS NOT NULL)
          AND (threat_name != '' OR threat_category != '')
          AND (
            threat_name IS NOT NULL AND threat_name != ''
            OR lower(COALESCE(threat_category, '')) NOT IN ('', 'benign', 'unknown')
          )
        """
    )


def init_graph(conn: duckdb.DuckDBPyConnection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_edges(
          src VARCHAR,
          dst VARCHAR,
          rel VARCHAR
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_events(
          entity VARCHAR,
          event_id BIGINT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS manual_edges(
          id VARCHAR,
          src VARCHAR,
          dst VARCHAR,
          rel VARCHAR,
          note VARCHAR,
          properties_json VARCHAR,
          created_at DOUBLE,
          deleted_at DOUBLE
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS deleted_edges(
          src VARCHAR,
          dst VARCHAR,
          rel VARCHAR,
          deleted_at DOUBLE,
          reason VARCHAR
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS entity_notes(
          id VARCHAR,
          node VARCHAR,
          note VARCHAR,
          source VARCHAR,
          created_at DOUBLE,
          deleted_at DOUBLE
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS entity_edges_src_idx ON entity_edges(src)")
    conn.execute("CREATE INDEX IF NOT EXISTS entity_edges_dst_idx ON entity_edges(dst)")
    conn.execute("CREATE INDEX IF NOT EXISTS entity_events_entity_idx ON entity_events(entity)")
    conn.execute("CREATE INDEX IF NOT EXISTS entity_events_event_idx ON entity_events(event_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS manual_edges_src_idx ON manual_edges(src)")
    conn.execute("CREATE INDEX IF NOT EXISTS manual_edges_dst_idx ON manual_edges(dst)")
    conn.execute("CREATE INDEX IF NOT EXISTS entity_notes_node_idx ON entity_notes(node)")


def materialize_entity_edges(conn: duckdb.DuckDBPyConnection) -> None:
    init_graph(conn)
    conn.execute(
        """
        CREATE OR REPLACE TABLE entity_edges AS
        SELECT DISTINCT src, dst, rel
        FROM graph_edges
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS entity_edges_src_idx ON entity_edges(src)")
    conn.execute("CREATE INDEX IF NOT EXISTS entity_edges_dst_idx ON entity_edges(dst)")


def materialize_entity_events(conn: duckdb.DuckDBPyConnection) -> None:
    init_graph(conn)
    conn.execute(
        """
        CREATE OR REPLACE TABLE entity_events AS
        SELECT DISTINCT 'ip:' || src_ip AS entity, event_id
        FROM firewall_logs
        WHERE src_ip IS NOT NULL

        UNION
        SELECT DISTINCT 'ip:' || dst_ip AS entity, event_id
        FROM firewall_logs
        WHERE dst_ip IS NOT NULL

        UNION
        SELECT DISTINCT 'user:' || src_user AS entity, event_id
        FROM firewall_logs
        WHERE src_user IS NOT NULL AND src_user != ''

        UNION
        SELECT DISTINCT 'domain:' || url_domain AS entity, event_id
        FROM firewall_logs
        WHERE url_domain IS NOT NULL AND url_domain != ''

        UNION
        SELECT DISTINCT 'threat:' || COALESCE(NULLIF(threat_name, ''), threat_category) AS entity,
          event_id
        FROM firewall_logs
        WHERE (threat_name IS NOT NULL OR threat_category IS NOT NULL)
          AND (threat_name != '' OR threat_category != '')
          AND (
            threat_name IS NOT NULL AND threat_name != ''
            OR lower(COALESCE(threat_category, '')) NOT IN ('', 'benign', 'unknown')
          )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS entity_events_entity_idx ON entity_events(entity)")
    conn.execute("CREATE INDEX IF NOT EXISTS entity_events_event_idx ON entity_events(event_id)")


def add_edge(
    conn: duckdb.DuckDBPyConnection,
    src: str,
    dst: str,
    rel: str,
    *,
    note: str = "",
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_graph(conn)
    edge_id = str(uuid.uuid4())
    record = {
        "id": edge_id,
        "src": src,
        "dst": dst,
        "rel": rel,
        "note": note,
        "properties_json": json.dumps(properties or {}, sort_keys=True),
        "created_at": time.time(),
        "deleted_at": None,
    }
    conn.execute(
        """
        INSERT INTO manual_edges
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        list(record.values()),
    )
    return record


def remove_edge(
    conn: duckdb.DuckDBPyConnection,
    src: str,
    dst: str,
    rel: str,
    *,
    reason: str = "",
) -> None:
    init_graph(conn)
    deleted_at = time.time()
    conn.execute(
        """
        INSERT INTO deleted_edges VALUES (?, ?, ?, ?, ?)
        """,
        [src, dst, rel, deleted_at, reason],
    )
    conn.execute(
        """
        UPDATE manual_edges
        SET deleted_at = ?
        WHERE src = ? AND dst = ? AND rel = ? AND deleted_at IS NULL
        """,
        [deleted_at, src, dst, rel],
    )


def add_note(
    conn: duckdb.DuckDBPyConnection,
    node: str,
    note: str,
    *,
    source: str = "manual",
) -> dict[str, Any]:
    init_graph(conn)
    record = {
        "id": str(uuid.uuid4()),
        "node": node,
        "note": note,
        "source": source,
        "created_at": time.time(),
        "deleted_at": None,
    }
    conn.execute("INSERT INTO entity_notes VALUES (?, ?, ?, ?, ?, ?)", list(record.values()))
    return record


def remove_note(conn: duckdb.DuckDBPyConnection, note_id: str) -> None:
    init_graph(conn)
    conn.execute(
        "UPDATE entity_notes SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL",
        [time.time(), note_id],
    )


def malware_hits(conn: duckdb.DuckDBPyConnection, limit: int = 50) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        WITH hits AS (
          SELECT
            ts,
            src_ip,
            dst_ip,
            src_user,
            url_domain,
            threat_name,
            threat_category,
            action,
            application,
            bytes,
            CASE
              WHEN lower(COALESCE(threat_category, '')) LIKE '%malware%' THEN 'category'
              WHEN lower(COALESCE(threat_name, '')) LIKE '%malware%' THEN 'name'
              WHEN lower(COALESCE(url_domain, '')) = lower(COALESCE(ti.indicator_value, ''))
                THEN 'intel-domain'
              WHEN COALESCE(dst_ip, '') = COALESCE(ti.indicator_value, '')
                THEN 'intel-ip'
              ELSE 'unknown'
            END AS match_reason,
            ti.malware_family,
            ti.severity
          FROM firewall_logs fl
          LEFT JOIN threat_intel ti
            ON lower(COALESCE(fl.url_domain, '')) = lower(COALESCE(ti.indicator_value, ''))
            OR COALESCE(fl.dst_ip, '') = COALESCE(ti.indicator_value, '')
          WHERE lower(COALESCE(threat_category, '')) LIKE '%malware%'
             OR lower(COALESCE(threat_name, '')) LIKE '%malware%'
             OR ti.indicator_value IS NOT NULL
        )
        SELECT * FROM hits
        ORDER BY ts DESC
        LIMIT ?
        """,
        [limit],
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def neighborhood(
    conn: duckdb.DuckDBPyConnection,
    seed: str,
    hops: int = 3,
    limit: int = 100,
) -> list[dict[str, Any]]:
    edge_relation = _effective_edges_sql(conn)
    rows = conn.execute(
        f"""
        WITH RECURSIVE walk(depth, node, path) AS (
          SELECT 0, ?::VARCHAR, ?::VARCHAR
          UNION ALL
          SELECT
            walk.depth + 1,
            graph_edges.dst,
            walk.path || ' -> ' || graph_edges.dst
          FROM walk
          JOIN ({edge_relation}) AS graph_edges ON graph_edges.src = walk.node
          WHERE walk.depth < ?
            AND strpos(walk.path, graph_edges.dst) = 0
        )
        SELECT DISTINCT depth, node, path
        FROM walk
        ORDER BY depth, node
        LIMIT ?
        """,
        [seed, seed, hops, limit],
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def related_events(
    conn: duckdb.DuckDBPyConnection,
    seed: str,
    hops: int = 2,
    limit: int = 100,
) -> list[dict[str, Any]]:
    init_graph(conn)
    if not _relation_exists(conn, "entity_events"):
        materialize_entity_events(conn)
    edge_relation = _effective_edges_sql(conn)
    rows = conn.execute(
        f"""
        WITH RECURSIVE related_nodes(depth, node, path) AS (
          SELECT 0, ?::VARCHAR, ?::VARCHAR
          UNION
          SELECT
            related_nodes.depth + 1,
            edges.dst,
            related_nodes.path || ' -> ' || edges.dst
          FROM related_nodes
          JOIN ({edge_relation}) edges ON edges.src = related_nodes.node
          WHERE related_nodes.depth < ?
            AND strpos(related_nodes.path, edges.dst) = 0
        ),
        event_hits AS (
          SELECT
            min(related_nodes.depth) AS depth,
            entity_events.event_id,
            string_agg(DISTINCT related_nodes.node, ', ' ORDER BY related_nodes.node)
              AS matched_entities
          FROM related_nodes
          JOIN entity_events ON entity_events.entity = related_nodes.node
          GROUP BY entity_events.event_id
        )
        SELECT
          event_hits.depth,
          event_hits.matched_entities,
          firewall_logs.*
        FROM event_hits
        JOIN firewall_logs ON firewall_logs.event_id = event_hits.event_id
        ORDER BY event_hits.depth, firewall_logs.ts DESC
        LIMIT ?
        """,
        [seed, seed, hops, limit],
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def graph_nodes(conn: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    init_graph(conn)
    rows = conn.execute(
        f"""
        WITH node_ids AS (
          SELECT src AS id FROM ({_effective_edges_sql(conn)})
          UNION
          SELECT dst AS id FROM ({_effective_edges_sql(conn)})
        )
        SELECT
          id,
          split_part(id, ':', 1) AS label
        FROM node_ids
        ORDER BY id
        """
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def graph_links(conn: duckdb.DuckDBPyConnection) -> list[dict[str, Any]]:
    init_graph(conn)
    rows = conn.execute(
        f"""
        SELECT DISTINCT src, dst, rel
        FROM ({_effective_edges_sql(conn)})
        ORDER BY src, dst, rel
        """
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def export_graph(
    conn: duckdb.DuckDBPyConnection,
    output_dir: str | Path,
    fmt: str,
) -> dict[str, str]:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    if fmt == "kuzu-csv":
        return _export_kuzu_csv(conn, out)
    if fmt == "memgraph-cypher":
        return _export_memgraph_cypher(conn, out)
    raise ValueError(f"unsupported export format: {fmt}")


def _export_kuzu_csv(conn: duckdb.DuckDBPyConnection, out: Path) -> dict[str, str]:
    nodes_path = out / "nodes.csv"
    edges_path = out / "edges.csv"
    cypher_path = out / "import.cypher"
    _write_csv(nodes_path, graph_nodes(conn), ["id", "label"])
    _write_csv(edges_path, graph_links(conn), ["src", "dst", "rel"])
    cypher_path.write_text(
        "\n".join(
            [
                "CREATE NODE TABLE IF NOT EXISTS Node(id STRING, label STRING, PRIMARY KEY(id));",
                "CREATE REL TABLE IF NOT EXISTS Edge(FROM Node TO Node, rel STRING);",
                f"COPY Node FROM '{nodes_path.name}' (HEADER=true);",
                f"COPY Edge FROM '{edges_path.name}' (HEADER=true);",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {"nodes": str(nodes_path), "edges": str(edges_path), "cypher": str(cypher_path)}


def _export_memgraph_cypher(conn: duckdb.DuckDBPyConnection, out: Path) -> dict[str, str]:
    cypher_path = out / "graph.cypher"
    lines = []
    for node in graph_nodes(conn):
        lines.append(
            "MERGE (:Entity {id: "
            + _cypher_string(node["id"])
            + ", label: "
            + _cypher_string(node["label"])
            + "});"
        )
    for edge in graph_links(conn):
        lines.append(
            "MATCH (a:Entity {id: "
            + _cypher_string(edge["src"])
            + "}), (b:Entity {id: "
            + _cypher_string(edge["dst"])
            + "}) MERGE (a)-[:RELATED {rel: "
            + _cypher_string(edge["rel"])
            + "}]->(b);"
        )
    cypher_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"cypher": str(cypher_path)}


def _cypher_string(value: object) -> str:
    return json_escape(str(value))


def json_escape(value: str) -> str:
    return json.dumps(value)


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _relation_exists(conn: duckdb.DuckDBPyConnection, name: str) -> bool:
    rows = conn.execute(
        "SELECT count(*) FROM information_schema.tables WHERE table_name = ?",
        [name],
    ).fetchone()
    return bool(rows and rows[0])


def _relation_count(conn: duckdb.DuckDBPyConnection, name: str) -> int:
    if not _relation_exists(conn, name):
        return 0
    return conn.execute(f"SELECT count(*) FROM {name}").fetchone()[0]


def _effective_edges_sql(conn: duckdb.DuckDBPyConnection) -> str:
    init_graph(conn)
    return """
      SELECT DISTINCT e.src, e.dst, e.rel
      FROM (
        SELECT src, dst, rel FROM entity_edges
        UNION ALL
        SELECT src, dst, rel FROM manual_edges WHERE deleted_at IS NULL
      ) e
      WHERE NOT EXISTS (
        SELECT 1
        FROM deleted_edges d
        WHERE d.src = e.src AND d.dst = e.dst AND d.rel = e.rel
      )
    """


def search_graph(
    conn: duckdb.DuckDBPyConnection,
    query: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    init_graph(conn)
    needle = f"%{query.lower()}%"
    rows = conn.execute(
        f"""
        WITH nodes AS (
          SELECT id AS item, 'node' AS kind, label AS detail
          FROM (
            SELECT
              id,
              split_part(id, ':', 1) AS label
            FROM (
              SELECT src AS id FROM ({_effective_edges_sql(conn)})
              UNION
              SELECT dst AS id FROM ({_effective_edges_sql(conn)})
            )
          )
          WHERE lower(id) LIKE ?
        ),
        notes AS (
          SELECT node AS item, 'note' AS kind, note AS detail
          FROM entity_notes
          WHERE deleted_at IS NULL
            AND (lower(node) LIKE ? OR lower(note) LIKE ?)
        )
        SELECT * FROM nodes
        UNION ALL
        SELECT * FROM notes
        LIMIT ?
        """,
        [needle, needle, needle, limit],
    ).fetchall()
    columns = [item[0] for item in conn.description]
    return [dict(zip(columns, row, strict=False)) for row in rows]


def generate_synthetic_logs(path: str | Path, rows: int) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    domains = ["updates.example.com", "bad.example", "cdn.example.net", "c2.example"]
    users = ["alice", "bob", "carol", "dave"]
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(LOG_COLUMNS)
        for index in range(rows):
            domain = domains[index % len(domains)]
            malware = domain in {"bad.example", "c2.example"}
            writer.writerow(
                [
                    f"2026-01-{index % 28 + 1:02d}T00:00:00Z",
                    f"10.0.{index % 256}.{index % 251 + 1}",
                    f"203.0.113.{index % 200 + 1}",
                    users[index % len(users)],
                    domain,
                    "Malware callback" if malware else "",
                    "malware" if malware else "benign",
                    "allow",
                    "web-browsing" if index % 3 else "dns",
                    300 + index % 5000,
                ]
            )


def benchmark(
    conn: duckdb.DuckDBPyConnection,
    csv_path: str | Path,
    rows: int,
    seed: str,
    hops: int = 2,
    limit: int = 100,
) -> dict[str, Any]:
    csv_path = Path(csv_path)
    start = time.perf_counter()
    generate_synthetic_logs(csv_path, rows)
    generated_seconds = time.perf_counter() - start

    start = time.perf_counter()
    ingest_result = ingest_sources(conn, csv_path)
    ingest_seconds = time.perf_counter() - start

    start = time.perf_counter()
    events = related_events(conn, seed, hops=hops, limit=limit)
    query_seconds = time.perf_counter() - start

    return {
        "rows": rows,
        "generated_seconds": round(generated_seconds, 3),
        "ingest_seconds": round(ingest_seconds, 3),
        "query_seconds": round(query_seconds, 3),
        "query_millis": round(query_seconds * 1000, 3),
        "returned_events": len(events),
        **ingest_result,
    }
