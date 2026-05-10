"""
One-time migration script: add auth_provider and password_hash columns to users table.
Run with: python migrate_auth.py
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')

from app.database.db import engine
from sqlalchemy import text

with engine.connect() as conn:
    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN auth_provider VARCHAR(20) NOT NULL DEFAULT 'github'"))
        print("OK: Added auth_provider column")
    except Exception as e:
        print(f"SKIP auth_provider: {e}")

    try:
        conn.execute(text("ALTER TABLE users ADD COLUMN password_hash TEXT"))
        print("OK: Added password_hash column")
    except Exception as e:
        print(f"SKIP password_hash: {e}")

    conn.commit()
    print("Migration complete!")

# Verify
with engine.connect() as conn:
    from sqlalchemy import inspect
    insp = inspect(engine)
    cols = [c["name"] for c in insp.get_columns("users")]
    print(f"Users table columns: {cols}")
