"""
AEGISX - Password Reset Email Service
Sends password reset emails via SMTP with secure time-limited tokens.
"""
import logging
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict

from app.core.config import settings

logger = logging.getLogger(__name__)


async def send_reset_email(to_email: str, reset_token: str, reset_url: str,
                            username: str = "User") -> bool:
    if not settings.SMTP_HOST or not settings.SMTP_FROM:
        logger.warning("SMTP not configured — reset email not sent to %s", to_email)
        return False

    subject = "AEGISX - Password Reset Request"
    body_html = f"""
    <html>
    <body style="font-family: -apple-system, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #1e3a5f, #0f172a); padding: 30px; border-radius: 12px 12px 0 0;">
            <h1 style="color: #38bdf8; margin: 0; font-size: 24px;">AEGISX</h1>
            <p style="color: #94a3b8; margin: 8px 0 0;">Enterprise Cybersecurity Platform</p>
        </div>
        <div style="background: #1e293b; padding: 30px; border-radius: 0 0 12px 12px;">
            <h2 style="color: #e2e8f0; margin: 0 0 12px;">Password Reset Request</h2>
            <p style="color: #cbd5e1; line-height: 1.6;">
                A password reset was requested for <strong>{username}</strong> ({to_email}).
            </p>
            <p style="color: #94a3b8; line-height: 1.6; font-size: 14px;">
                Click the button below to reset your password. This link expires in
                <strong>{settings.JWT_RESET_TOKEN_EXPIRE_HOURS} hour(s)</strong>.
            </p>
            <div style="text-align: center; margin: 28px 0;">
                <a href="{reset_url}?token={reset_token}"
                   style="background: #38bdf8; color: #0f172a; padding: 14px 36px;
                          border-radius: 8px; text-decoration: none; font-weight: 600;
                          font-size: 15px; display: inline-block;">
                    Reset Password
                </a>
            </div>
            <p style="color: #64748b; font-size: 12px; line-height: 1.6;">
                If you didn't request this, ignore this email. Your password won't change.
                <br>If the button doesn't work, copy this link:
                <br><code style="color: #38bdf8; font-size: 11px;">{reset_url}?token={reset_token}</code>
            </p>
            <hr style="border: none; border-top: 1px solid #334155; margin: 24px 0;">
            <p style="color: #475569; font-size: 11px;">
                This is an automated security notification from AEGISX.
                Requested at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}.
            </p>
        </div>
    </body>
    </html>
    """

    body_text = (
        f"Password Reset Request for {username} ({to_email})\n\n"
        f"Click this link to reset your password:\n{reset_url}?token={reset_token}\n\n"
        f"This link expires in {settings.JWT_RESET_TOKEN_EXPIRE_HOURS} hour(s).\n"
        f"If you didn't request this, ignore this email."
    )

    try:
        import smtplib

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to_email
        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        if settings.SMTP_TLS:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30)

        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)

        server.sendmail(settings.SMTP_FROM, [to_email], msg.as_string())
        server.quit()

        logger.info("Password reset email sent to %s", to_email)
        return True
    except Exception as e:
        logger.error("Failed to send reset email to %s: %s", to_email, e)
        return False
