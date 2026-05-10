"""
Migration: Add email verification OTP columns to the users table.
Run once: python migrate_otp.py
"""
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "ark_local.db")

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Get existing columns
    cur.execute("PRAGMA table_info(users)")
    cols = {row[1] for row in cur.fetchall()}

    added = []
    if "is_email_verified" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN is_email_verified INTEGER NOT NULL DEFAULT 0")
        added.append("is_email_verified")

    if "email_otp_hash" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN email_otp_hash TEXT")
        added.append("email_otp_hash")

    if "email_otp_expires_at" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN email_otp_expires_at DATETIME")
        added.append("email_otp_expires_at")

    # Mark all EXISTING email users as verified (don't break existing accounts)
    cur.execute(
        "UPDATE users SET is_email_verified = 1 WHERE auth_provider = 'email' AND is_email_verified = 0"
    )
    updated = cur.rowcount

    # Mark GitHub users as verified (they're always verified via GitHub)
    cur.execute(
        "UPDATE users SET is_email_verified = 1 WHERE auth_provider = 'github' AND is_email_verified = 0"
    )
    gh_updated = cur.rowcount

    conn.commit()
    conn.close()

    print(f"Migration complete!")
    print(f"  Columns added: {added or 'none (already existed)'}")
    print(f"  Existing email users marked as verified: {updated}")
    print(f"  GitHub users marked as verified: {gh_updated}")

if __name__ == "__main__":
    migrate()
