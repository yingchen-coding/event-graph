# Event Graph

Event Graph is a fast entity/event index for large logs.

It is not a graph visualization tool. It is an indexing pattern:

1. Ingest events.
2. Extract entities and relationships.
3. Build compact `entity_edges(src, dst, rel)` and `entity_events(entity, event_id)` tables.
4. Query from one entity to all related events without scanning the whole raw dataset.

This can be used for security logs, agent traces, audit logs, product events, support tickets,
financial transactions, workflow histories, or anything else where records are connected by
entities.

## Why This Works

The scalable pattern is:

- keep high-volume raw events in columnar/relational storage;
- materialize compact `entity_edges(src, dst, rel)`;
- materialize compact `entity_events(entity, event_id)` as an inverted index;
- query by expanding related entities first, then join only matching `event_id`s back to raw events;
- store analyst/user edges and notes as overlays instead of rewriting raw data;
- delete edges/notes with tombstones so investigations stay auditable.

DuckDB is used here as the local scan/index engine. KuzuDB and Memgraph are useful next steps when
you want a dedicated graph runtime; this repo can export Kuzu-style CSV and Memgraph-style Cypher.

## Generic Input

Generic event CSV/JSON/Parquet should contain:

`ts, src, dst, rel`

Optional columns are preserved and returned with matching events.

Example:

```csv
ts,src,dst,rel,details
2026-01-01T00:00:00Z,user:alice,service:billing,used,opened billing page
2026-01-01T00:00:01Z,service:billing,file:invoice.pdf,touched,generated export
```

## Install

```bash
python -m pip install -e '.[dev]'
```

## Quick Start

```bash
event-graph generate-synthetic /tmp/events.csv --rows 100000
event-graph --db /tmp/events.duckdb ingest --events /tmp/events.csv
event-graph --db /tmp/events.duckdb related-events user:alice --hops 2 --limit 20
```

Add context without mutating raw events:

```bash
event-graph --db /tmp/events.duckdb add-edge user:alice owns ticket:INC-123 \
  --note "Manual analyst link"

event-graph --db /tmp/events.duckdb add-note user:alice "Repeated export failures"
event-graph --db /tmp/events.duckdb search export
```

Benchmark:

```bash
event-graph --db /tmp/events.duckdb benchmark --rows 1000000 \
  --seed user:alice --hops 2 --limit 100
```

## Security Adapter Example

Security logs are one adapter, not the whole product.

Expected security columns:

`ts, src_ip, dst_ip, src_user, url_domain, threat_name, threat_category, action, application, bytes`

```bash
event-graph --db demo.duckdb load-sample
event-graph --db demo.duckdb malware-hits
event-graph --db demo.duckdb related-events domain:bad.example --hops 2
```

Generate a synthetic security dataset:

```bash
event-graph generate-synthetic-security /tmp/fw.csv --rows 1000000
event-graph --db /tmp/fw.duckdb ingest-security --logs /tmp/fw.csv
event-graph --db /tmp/fw.duckdb related-events domain:bad.example --hops 2 --limit 20
```

Observed local security benchmark on this machine:

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

## Exports

```bash
event-graph --db /tmp/events.duckdb export kuzu-csv /tmp/kuzu
event-graph --db /tmp/events.duckdb export memgraph-cypher /tmp/memgraph
```

## What To Build Next

- Config-driven entity extraction from arbitrary schemas.
- Parquet/Iceberg partition pruning.
- Incremental append without full index rebuild.
- Larger 10M+ event benchmark.
- Adapters for security, agent traces, product analytics, audit logs, and ticket systems.
