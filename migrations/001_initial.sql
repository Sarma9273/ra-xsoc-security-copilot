-- RA-XSOC-X PostgreSQL schema v1
CREATE TABLE IF NOT EXISTS analysis_cases (
    analysis_id UUID PRIMARY KEY,
    incident_id UUID NOT NULL,
    payload JSONB NOT NULL,
    review_status VARCHAR(32) NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analysis_cases_incident_id ON analysis_cases (incident_id);
CREATE INDEX IF NOT EXISTS idx_analysis_cases_review_status ON analysis_cases (review_status);
CREATE INDEX IF NOT EXISTS idx_analysis_cases_created_at ON analysis_cases (created_at);

CREATE TABLE IF NOT EXISTS feedback (
    feedback_id UUID PRIMARY KEY,
    analysis_id UUID NOT NULL REFERENCES analysis_cases(analysis_id),
    analyst_id UUID NOT NULL,
    status VARCHAR(32) NOT NULL,
    comments TEXT NOT NULL,
    corrected_attack_id VARCHAR(200),
    created_at VARCHAR(64) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_feedback_analysis_id ON feedback (analysis_id);
