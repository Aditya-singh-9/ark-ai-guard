"""
Migration script: add OTP email-verification columns to the users table (SQLite-safe),
then mark all pre-existing email users as verified so they are not locked out.
"""
from app.database.db import engine, Base
from app.models import user  # noqa: ensure model is imported
from sqlalchemy import text, inspect

with engine.connect() as conn:
    # 1. Add missing columns if they don't exist yet (SQLite has no IF NOT EXISTS for ADD COLUMN before 3.37)
    inspector = inspect(engine)
    existing_cols = {c["name"] for c in inspector.get_columns("users")}

    if "is_email_verified" not in existing_cols:
        conn.execute(text("ALTER TABLE users ADD COLUMN is_email_verified INTEGER NOT NULL DEFAULT 0"))
        print("Added column: is_email_verified")

    if "email_otp_hash" not in existing_cols:
        conn.execute(text("ALTER TABLE users ADD COLUMN email_otp_hash VARCHAR(64)"))
        print("Added column: email_otp_hash")

    if "email_otp_expires_at" not in existing_cols:
        conn.execute(text("ALTER TABLE users ADD COLUMN email_otp_expires_at DATETIME"))
        print("Added column: email_otp_expires_at")

    # 2. Mark ALL existing email users as verified (they registered before OTP enforcement)
    result = conn.execute(
        text("UPDATE users SET is_email_verified=1 WHERE auth_provider='email'")
    )
    conn.commit()
    print(f"Migration OK: {result.rowcount} existing email user(s) marked as verified.")

# 3. Also run SQLAlchemy create_all to sync any other schema changes
Base.metadata.create_all(engine)
print("Schema sync complete.")
