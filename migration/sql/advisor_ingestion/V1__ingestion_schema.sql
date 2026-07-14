CREATE TABLE component (
    id              BIGSERIAL       PRIMARY KEY,
    analysis_run_id UUID            NOT NULL,
    purl            TEXT            NOT NULL,
    group_id        TEXT            NOT NULL,
    artifact_id     TEXT            NOT NULL,
    version         TEXT            NOT NULL,
    direct          BOOLEAN         NOT NULL,
    depth           INTEGER         NOT NULL,
    path            TEXT,
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX idx_component_analysis_run ON component(analysis_run_id);
