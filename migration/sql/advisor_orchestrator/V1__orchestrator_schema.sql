CREATE TABLE analysis_run (
    id UUID PRIMARY KEY,
    repo_url TEXT NOT NULL,
    commit_sha TEXT,
    status TEXT NOT NULL, -- QUEUED, RUNNING, COMPLETED, FAILED
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at  TIMESTAMPTZ
);

CREATE TABLE stage_execution (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES analysis_run (id),
    stage_name TEXT NOT NULL,
    status TEXT NOT NULL, -- RUNNING, COMPLETED, FAILED
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms BIGINT,
    attempt INT NOT NULL DEFAULT 1,
    error TEXT
);

CREATE INDEX idx_stage_execution_run ON stage_execution (run_id);