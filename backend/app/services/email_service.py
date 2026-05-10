"""
Email service — sends transactional emails via SMTP (TLS/SSL).

Configured via environment variables / .env:
  SMTP_SERVER       e.g.  smtp.gmail.com
  SMTP_PORT         e.g.  587  (STARTTLS) or 465 (SSL)
  SMTP_USERNAME     your Gmail / SMTP account
  SMTP_PASSWORD     app password (not your login password)
  SMTP_FROM_EMAIL   display sender e.g. "ARK Guard <noreply@yourapp.com>"

If SMTP_SERVER is not set the email is printed to the terminal (dev mode).
"""
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from app.utils.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)


# ── HTML email templates ───────────────────────────────────────────────────────

PASSWORD_RESET_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Reset Your Password — ARK DevScops Guard</title>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0"
             style="background:#161b22;border-radius:12px;border:1px solid #30363d;overflow:hidden;max-width:600px;">
        <!-- Header -->
        <tr>
          <td style="background:linear-gradient(135deg,#1f6feb 0%,#58a6ff 100%);
                     padding:32px 40px;text-align:center;">
            <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;letter-spacing:-0.5px;">
              🛡️ ARK DevScops Guard
            </h1>
            <p style="margin:8px 0 0;color:rgba(255,255,255,0.85);font-size:14px;">
              Security-first DevSecOps Platform
            </p>
          </td>
        </tr>
        <!-- Body -->
        <tr>
          <td style="padding:40px;">
            <h2 style="margin:0 0 16px;color:#e6edf3;font-size:20px;font-weight:600;">
              Reset your password
            </h2>
            <p style="margin:0 0 24px;color:#8b949e;font-size:15px;line-height:1.6;">
              Hi <strong style="color:#e6edf3;">{username}</strong>,<br/><br/>
              We received a request to reset the password for your account associated with
              <strong style="color:#58a6ff;">{email}</strong>.
              If you didn't make this request, you can safely ignore this email.
            </p>
            <!-- CTA Button -->
            <table cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td align="center" style="padding:8px 0 32px;">
                  <a href="{reset_url}"
                     style="display:inline-block;background:linear-gradient(135deg,#1f6feb,#58a6ff);
                            color:#fff;text-decoration:none;font-size:15px;font-weight:600;
                            padding:14px 36px;border-radius:8px;letter-spacing:0.3px;">
                    Reset Password
                  </a>
                </td>
              </tr>
            </table>
            <p style="margin:0 0 8px;color:#8b949e;font-size:13px;">
              Or copy this link into your browser:
            </p>
            <p style="margin:0 0 24px;font-size:12px;word-break:break-all;">
              <a href="{reset_url}" style="color:#58a6ff;">{reset_url}</a>
            </p>
            <hr style="border:none;border-top:1px solid #30363d;margin:0 0 24px;" />
            <p style="margin:0;color:#6e7681;font-size:12px;line-height:1.6;">
              ⏰ This link expires in <strong>30 minutes</strong>.<br/>
              🔒 For security, this link can only be used once.
            </p>
          </td>
        </tr>
        <!-- Footer -->
        <tr>
          <td style="background:#0d1117;padding:20px 40px;text-align:center;
                     border-top:1px solid #21262d;">
            <p style="margin:0;color:#6e7681;font-size:12px;">
              ARK DevScops Guard · Secure your code, secure your future.<br/>
              You're receiving this because a password reset was requested for your account.
            </p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>
"""

PASSWORD_RESET_TEXT = """\
Reset your ARK DevScops Guard password
=======================================

Hi {username},

We received a request to reset the password for your account ({email}).

Click the link below to reset your password (expires in 30 minutes):

  {reset_url}

If you didn't request a password reset, you can safely ignore this email.

— ARK DevScops Guard Team
"""


# ── Core send function ─────────────────────────────────────────────────────────

def send_password_reset_email(to_email: str, username: str, reset_url: str) -> bool:
    """
    Send a password-reset email.

    Returns True on success, False on failure (errors are logged, never raised).
    In dev mode (no SMTP_SERVER set), prints the link to the terminal.
    """
    subject = "Reset your ARK DevScops Guard password"
    html_body = PASSWORD_RESET_HTML.format(
        username=username, email=to_email, reset_url=reset_url
    )
    text_body = PASSWORD_RESET_TEXT.format(
        username=username, email=to_email, reset_url=reset_url
    )

    # ── Dev/fallback mode (no SMTP configured) ─────────────────────────────────
    if not settings.SMTP_SERVER or not settings.SMTP_USERNAME:
        log.warning(
            "[EMAIL DEV MODE] SMTP not configured — printing reset link to terminal:\n"
            f"  To:  {to_email}\n"
            f"  URL: {reset_url}"
        )
        print(f"\n{'='*60}")
        print(f"PASSWORD RESET EMAIL (dev mode — no SMTP configured)")
        print(f"  To:      {to_email}")
        print(f"  Subject: {subject}")
        print(f"  Link:    {reset_url}")
        print(f"{'='*60}\n")
        return True  # Treat as success so the flow doesn't break

    # ── Production SMTP send ───────────────────────────────────────────────────
    from_addr = settings.SMTP_FROM_EMAIL or settings.SMTP_USERNAME

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        ctx = ssl.create_default_context()

        if settings.SMTP_PORT == 465:
            # SSL from the start (older providers)
            with smtplib.SMTP_SSL(settings.SMTP_SERVER, settings.SMTP_PORT, context=ctx) as server:
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.sendmail(from_addr, to_email, msg.as_string())
        else:
            # STARTTLS (port 587 — recommended)
            with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT, timeout=15) as server:
                server.ehlo()
                server.starttls(context=ctx)
                server.ehlo()
                server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                server.sendmail(from_addr, to_email, msg.as_string())

        log.info(f"[Email] Password-reset email sent to {to_email}")
        return True

    except smtplib.SMTPAuthenticationError:
        log.error(
            "[Email] SMTP authentication failed. "
            "Check SMTP_USERNAME and SMTP_PASSWORD in .env. "
            "For Gmail, use an App Password (not your login password)."
        )
    except smtplib.SMTPException as exc:
        log.error(f"[Email] SMTP error sending to {to_email}: {exc}")
    except Exception as exc:
        log.error(f"[Email] Unexpected error sending email: {exc}")

    return False
