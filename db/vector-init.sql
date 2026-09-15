CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS approved_queries (
  id text PRIMARY KEY,
  name text NOT NULL,
  description text NOT NULL,
  sql_text text NOT NULL,
  sql_hash char(64) NOT NULL,
  catalog_hash char(64) NOT NULL,
  parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
  min_role text NOT NULL CHECK (min_role IN ('viewer', 'analyst', 'admin')),
  min_role_level smallint NOT NULL CHECK (min_role_level BETWEEN 1 AND 3),
  sensitivity text NOT NULL CHECK (sensitivity IN ('low', 'medium', 'high')),
  sensitivity_level smallint NOT NULL CHECK (sensitivity_level BETWEEN 1 AND 3),
  source_commit text NOT NULL,
  source_path text NOT NULL,
  source_url text NOT NULL,
  embedding vector(384) NOT NULL,
  synced_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS approved_queries_access_idx
  ON approved_queries (min_role_level, sensitivity_level);
CREATE INDEX IF NOT EXISTS approved_queries_embedding_idx
  ON approved_queries USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id uuid NOT NULL UNIQUE,
  user_id text NOT NULL,
  user_email text NOT NULL,
  organization_id text NOT NULL,
  role text NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
  outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
  catalog_id text,
  sql_hash char(64),
  source_commit text,
  parameter_names jsonb NOT NULL DEFAULT '[]'::jsonb,
  estimated_cost double precision,
  estimated_rows bigint,
  actual_rows integer,
  duration_ms double precision,
  error_category text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_events_org_created_idx
  ON audit_events (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_user_created_idx
  ON audit_events (user_id, created_at DESC);
