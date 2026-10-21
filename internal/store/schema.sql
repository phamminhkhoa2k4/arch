-- Archaeologist v0.1 schema.
-- Append-only per scan: rows carry scan_id; evidence is never rewritten.

CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY,
    hostname      TEXT NOT NULL,
    os            TEXT,
    kernel        TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id                       INTEGER PRIMARY KEY,
    started_at               TEXT NOT NULL,
    finished_at              TEXT,
    host_id                  INTEGER NOT NULL REFERENCES hosts(id),
    tool_version             TEXT NOT NULL,
    collector_versions_json  TEXT NOT NULL DEFAULT '{}',
    status                   TEXT NOT NULL DEFAULT 'ok'
        CHECK (status IN ('ok', 'partial', 'failed'))
);

CREATE TABLE IF NOT EXISTS entities (
    id              INTEGER PRIMARY KEY,
    scan_id         INTEGER NOT NULL REFERENCES scans(id),
    kind            TEXT NOT NULL,
    name            TEXT NOT NULL,
    identity_key    TEXT NOT NULL,
    fingerprint     TEXT NOT NULL,
    attributes_json TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    UNIQUE (scan_id, identity_key)
);

CREATE TABLE IF NOT EXISTS evidence (
    id          INTEGER PRIMARY KEY,
    entity_id   INTEGER NOT NULL REFERENCES entities(id),
    polarity    TEXT NOT NULL CHECK (polarity IN ('in_use', 'not_in_use', 'neutral')),
    channel     TEXT NOT NULL,
    strength    TEXT NOT NULL
        CHECK (strength IN ('deterministic', 'strong_heuristic', 'weak_heuristic')),
    observed_at TEXT NOT NULL,
    raw_ref     TEXT NOT NULL CHECK (raw_ref <> ''),
    value_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS edges (
    id            INTEGER PRIMARY KEY,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    src_id        INTEGER NOT NULL REFERENCES entities(id),
    dst_id        INTEGER NOT NULL REFERENCES entities(id),
    kind          TEXT NOT NULL,
    strength      TEXT NOT NULL
        CHECK (strength IN ('deterministic', 'strong_heuristic', 'weak_heuristic')),
    evidence_id   INTEGER NOT NULL REFERENCES evidence(id),
    UNIQUE (scan_id, src_id, dst_id, kind)
);

CREATE TABLE IF NOT EXISTS observations (
    id           INTEGER PRIMARY KEY,
    entity_id    INTEGER NOT NULL REFERENCES entities(id),
    remote_key   TEXT NOT NULL,
    bucket_start TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    last_seen_at TEXT NOT NULL,
    UNIQUE (entity_id, remote_key, bucket_start)
);

CREATE TABLE IF NOT EXISTS blind_spots (
    id           INTEGER PRIMARY KEY,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    entity_id    INTEGER REFERENCES entities(id),
    channel      TEXT NOT NULL,
    reason       TEXT NOT NULL,
    detail_json  TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdicts (
    id                       INTEGER PRIMARY KEY,
    entity_id                INTEGER NOT NULL REFERENCES entities(id),
    scan_id                  INTEGER NOT NULL REFERENCES scans(id),
    state                    TEXT NOT NULL
        CHECK (state IN ('ACTIVE', 'LIKELY_ORPHANED', 'ORPHANED', 'UNKNOWN')),
    coverage                 TEXT NOT NULL CHECK (coverage IN ('HIGH', 'MEDIUM', 'LOW')),
    blockers_json            TEXT NOT NULL DEFAULT '[]',
    signals_json             TEXT NOT NULL DEFAULT '[]',
    blind_spots_json         TEXT NOT NULL DEFAULT '[]',
    observation_window_json  TEXT NOT NULL DEFAULT '{}',
    reasons_json             TEXT NOT NULL DEFAULT '[]',
    rules_hash               TEXT NOT NULL,
    computed_at              TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY,
    scan_id      INTEGER NOT NULL REFERENCES scans(id),
    entity_id    INTEGER NOT NULL REFERENCES entities(id),
    kind         TEXT NOT NULL
        CHECK (kind IN ('BROKEN_ROUTE', 'ORPHAN_CRON', 'UNUSED_IMAGE',
                        'UNUSED_VOLUME', 'DANGLING_DEPENDS')),
    severity     TEXT NOT NULL CHECK (severity IN ('info', 'warn')),
    detail_json  TEXT NOT NULL DEFAULT '{}',
    evidence_id  INTEGER REFERENCES evidence(id)
);

CREATE TABLE IF NOT EXISTS plans (
    id             INTEGER PRIMARY KEY,
    entity_id      INTEGER NOT NULL REFERENCES entities(id),
    created_at     TEXT NOT NULL,
    current_stage  TEXT NOT NULL DEFAULT 'Candidate'
);

CREATE TABLE IF NOT EXISTS plan_stages (
    id           INTEGER PRIMARY KEY,
    plan_id      INTEGER NOT NULL REFERENCES plans(id),
    stage        TEXT NOT NULL
        CHECK (stage IN ('Candidate', 'Quarantined', 'Observed',
                         'Archived', 'Removed', 'Verified')),
    status       TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'done')),
    confirmed_at TEXT,
    UNIQUE (plan_id, stage)
);

CREATE INDEX IF NOT EXISTS idx_entities_scan_kind ON entities (scan_id, kind);
CREATE INDEX IF NOT EXISTS idx_entities_identity ON entities (identity_key);
CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence (entity_id);
CREATE INDEX IF NOT EXISTS idx_edges_scan ON edges (scan_id);
CREATE INDEX IF NOT EXISTS idx_edges_scan_src ON edges (scan_id, src_id);
CREATE INDEX IF NOT EXISTS idx_edges_scan_dst ON edges (scan_id, dst_id);
CREATE INDEX IF NOT EXISTS idx_edges_scan_kind ON edges (scan_id, kind);
CREATE INDEX IF NOT EXISTS idx_blind_spots_scan ON blind_spots (scan_id);
CREATE INDEX IF NOT EXISTS idx_blind_spots_entity ON blind_spots (entity_id);
CREATE INDEX IF NOT EXISTS idx_observations_entity ON observations (entity_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
