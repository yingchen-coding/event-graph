# Security Graph

Security Graph is a local PuppyGraph/Memgraph/Kuzu-inspired prototype for threat hunting.

It is not a graph visualization tool. It is a fast entity index over security logs.

The core job is practical: ingest millions of firewall events, extract entities, connect them as
edges, and quickly return all events related to a user/IP/domain/threat without scanning every raw
log row at query time.

## Why This Works

The scalable pattern is:

- keep high-volume logs in columnar/relational storage;
- materialize compact `entity_edges(src, dst, rel)` from raw logs;
- materialize compact `entity_events(entity, event_id)` as the lookup index;
- query by expanding related entities first, then join only matching `event_id`s back to logs;
- store analyst edges/notes as overlays instead of rewriting raw logs;
- delete edges/notes with tombstones so investigations stay auditable.

DuckDB is used here as the local scan/index engine. KuzuDB and Memgraph are useful next steps when
you want a dedicated graph runtime; this repo can export Kuzu-style CSV and Memgraph-style Cypher.

## Data Model

Raw logs stay in `firewall_logs`.

Ingest builds two compact lookup tables:

- `entity_edges(src, dst, rel)`: graph links derived from logs, for example
  `user:alice -> ip:10.0.0.5 -> domain:bad.example -> threat:Malware callback`.
- `entity_events(entity, event_id)`: inverted index from entity to raw log event.

Query flow:

1. Start from a seed entity such as `domain:bad.example`.
2. Expand connected entities for `N` hops through `entity_edges`.
3. Join those entities to `entity_events`.
4. Fetch only matching rows from `firewall_logs`.

Manual analyst context uses overlays:

- `manual_edges`: add relationship without changing raw logs.
- `entity_notes`: add notes to an entity.
- `deleted_edges`: tombstone/suppress bad edges without mutating logs.

This is built for search speed and auditability, not graph visualization.

## Install

```bash
python -m pip install -e '.[dev]'
```

## Quick Start

```bash
security-graph --db demo.duckdb load-sample
security-graph --db demo.duckdb malware-hits
security-graph --db demo.duckdb related-events user:alice --hops 3
```

Ingest raw log files:

```bash
security-graph --db prod.duckdb ingest \
  --logs examples/firewall_logs.csv \
  --threat-intel examples/threat_intel.csv

security-graph --db prod.duckdb related-events domain:bad.example --hops 2
```

Add analyst context without mutating logs:

```bash
security-graph --db prod.duckdb add-edge user:alice suspected_compromise threat:ExampleRAT \
  --note "Repeated callbacks after initial hit"

security-graph --db prod.duckdb add-note ip:10.0.0.5 "Seen in incident INC-123"
security-graph --db prod.duckdb search INC-123
```

Generate synthetic logs for local speed testing:

```bash
security-graph generate-synthetic /tmp/fw.csv --rows 1000000
security-graph --db /tmp/fw.duckdb ingest --logs /tmp/fw.csv
security-graph --db /tmp/fw.duckdb related-events domain:bad.example --hops 2 --limit 20
```

Local benchmark on this machine:

```bash
security-graph --db /tmp/fw.duckdb benchmark --rows 1000000 \
  --seed domain:bad.example --hops 2 --limit 100
```

Observed result:

```json
{
  "rows": 1000000,
  "ingest_seconds": 5.145,
  "query_millis": 450.566,
  "returned_events": 100,
  "entity_edges": 1064556,
  "entity_events": 4500000
}
```

## Expected Firewall Log Columns

`ts, src_ip, dst_ip, src_user, url_domain, threat_name, threat_category, action, application, bytes`

## What To Build Next

- Partition-aware date filters for one-year log lakes.
- Real Palo Alto field mapping profiles.
- Parquet/Iceberg table support examples.
- More graph patterns: lateral movement, repeated failed auth, beaconing, exfiltration.
- Benchmark generator for 10M+ synthetic events.
