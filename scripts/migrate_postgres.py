from pathlib import Path
import os
import psycopg

url = os.environ["RA_XSOC_DATABASE_URL"]
sql = Path(__file__).resolve().parents[1] / "migrations" / "001_initial.sql"
with psycopg.connect(url) as conn:
    conn.execute(sql.read_text(encoding="utf-8"))
    conn.commit()
print("RA-XSOC PostgreSQL schema applied.")
