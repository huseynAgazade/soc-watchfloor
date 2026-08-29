-- SOC Watchfloor — initial schema stub.
-- Multi-tenant: every business row carries customer_id, and row-level security
-- enforces the session's tenant scope a second time under the application.
-- This is a scaffold; columns are illustrative. See docs/ARCHITECTURE.md §5.

CREATE TABLE IF NOT EXISTS customers (
    id           TEXT PRIMARY KEY,          -- also the SOAR label (join key)
    name         TEXT NOT NULL,
    contact      TEXT,
    tier         TEXT,
    modules      TEXT[] NOT NULL DEFAULT '{}',
    state        TEXT NOT NULL DEFAULT 'active',   -- active | archived
    onboarded_at DATE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id                   BIGSERIAL PRIMARY KEY,
    username             TEXT UNIQUE NOT NULL,
    full_name            TEXT NOT NULL,
    email                TEXT,
    phone                TEXT,
    chat_handle          TEXT,
    role                 TEXT NOT NULL,     -- soc_manager|shift_lead|soc_engineer|l2_analyst|l1_analyst|read_only
    team                 TEXT,              -- analysts | engineers | mgmt
    grade                TEXT,
    rota_grants          TEXT[] NOT NULL DEFAULT '{}',   -- {analysts,engineers}
    allowed_customer_ids TEXT[] NOT NULL DEFAULT '{}',   -- empty = all
    password_hash        TEXT,
    totp_secret_enc      TEXT,
    mfa_enrolled         BOOLEAN NOT NULL DEFAULT false,
    must_change_password BOOLEAN NOT NULL DEFAULT true,
    state                TEXT NOT NULL DEFAULT 'pending', -- active|pending|disabled
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The query catalog: each widget binds to one metric.
CREATE TABLE IF NOT EXISTS metrics (
    id           TEXT PRIMARY KEY,          -- e.g. siem.case_volume
    name         TEXT NOT NULL,
    source       TEXT NOT NULL,             -- splunk|soar|roster|detection|grafana
    widget       TEXT,
    query        TEXT,                      -- SPL with $index$/$earliest$/$latest$ (splunk only)
    binding      TEXT,                      -- description for non-splunk sources
    result_cols  JSONB,                     -- [[name,type],...] contract
    version      INT NOT NULL DEFAULT 1,
    updated_by   TEXT,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS metric_versions (
    metric_id  TEXT NOT NULL REFERENCES metrics(id),
    version    INT NOT NULL,
    query      TEXT,
    changed_by TEXT,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (metric_id, version)
);

-- Append-only audit.
CREATE TABLE IF NOT EXISTS audit_events (
    id       BIGSERIAL PRIMARY KEY,
    kind     TEXT NOT NULL,                 -- login.success, user.created, datasource.changed, ...
    detail   TEXT,
    actor    TEXT,
    at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
