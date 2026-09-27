# RA-XSOC-X Production Runbook

## Configuration

Required:
- RA_XSOC_DATABASE_URL
- RA_XSOC_AUTH_REQUIRED=true
- RA_XSOC_AUTH_TOKENS

Generate a unique token and store it in the deployment secret manager. Never commit credentials.

## Database

Apply the versioned schema:

`python scripts/migrate_postgres.py`

## API

Start:

`uvicorn ra_xsoc_api.main:app --host 0.0.0.0 --port 8000`

Verify:
- GET /health
- GET /ready
- authenticated GET /api/v1/cases

## Reports

Authenticated users can retrieve:

`GET /api/v1/cases/{analysis_id}/report.html`

## Safety

The system provides analyst decision support. It does not autonomously contain hosts, block accounts, delete evidence, or execute arbitrary remediation commands.
