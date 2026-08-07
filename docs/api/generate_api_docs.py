"""
AEGIS API Reference Generator
Generates standalone Markdown and PDF API documentation from OpenAPI schema.
Usage: python docs/api/generate_api_docs.py [--format md|pdf|both]
"""
import json, sys, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "backend"))


def generate_markdown_docs():
    """Extract OpenAPI schema and generate Markdown docs."""
    from app.main import app

    schema = app.openapi()

    doc = f"""# AEGIS API Reference v{schema['info']['version']}

{schema['info']['description']}

**Base URL:** `/api/v1`
**Authentication:** Bearer JWT token in Authorization header
**Multi-Tenancy:** X-Tenant-ID header required for most endpoints

---

## Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /auth/login | Login with email/password |
| POST | /auth/refresh | Refresh access token |
| POST | /auth/logout | Invalidate session |
| POST | /auth/mfa/verify | Verify MFA code |
| POST | /auth/mfa/setup | Setup MFA (TOTP) |
| POST | /auth/password/reset-request | Request password reset |
| POST | /auth/password/change | Change password |
| POST | /auth/webauthn/register | Register passkey |
| POST | /auth/api-key/generate | Generate API key |

---

## Endpoints by Category

"""
    tags = {}
    for path, methods in schema["paths"].items():
        for method, details in methods.items():
            if method in ["get", "post", "put", "patch", "delete"]:
                tag = details.get("tags", ["Uncategorized"])[0]
                if tag not in tags:
                    tags[tag] = []
                tags[tag].append(
                    {
                        "method": method.upper(),
                        "path": path.replace("/api/v1", ""),
                        "summary": details.get("summary", ""),
                        "description": details.get("description", ""),
                    }
                )

    for tag, endpoints in sorted(tags.items()):
        doc += f"### {tag}\n\n"
        doc += "| Method | Endpoint | Description |\n"
        doc += "|--------|----------|-------------|\n"
        for ep in endpoints:
            doc += f"| {ep['method']} | `{ep['path']}` | {ep['summary']} |\n"
        doc += "\n"

    for tag, endpoints in sorted(tags.items()):
        doc += f"## {tag} â€” Detailed\n\n"
        for ep in endpoints:
            doc += f"### {ep['method']} {ep['path']}\n\n"
            doc += f"{ep['description']}\n\n"
            doc += f"**Endpoint:** `{ep['method']} /api/v1{ep['path']}`\n\n"
            doc += "---\n\n"

    doc += """
## Error Codes

| Code | Meaning |
|------|---------|
| 400 | Bad Request â€” invalid input |
| 401 | Unauthorized â€” missing/invalid token |
| 403 | Forbidden â€” insufficient permissions |
| 404 | Not Found â€” resource doesn't exist |
| 409 | Conflict â€” duplicate resource |
| 422 | Validation Error â€” invalid fields |
| 429 | Rate Limited â€” too many requests |
| 500 | Internal Server Error |

## Rate Limits

| Endpoint Group | Limit |
|---------------|-------|
| Auth endpoints | 10 requests/minute per IP |
| API endpoints | 100 requests/minute per IP |

---

*Generated from OpenAPI schema â€” AEGIS Platform v1.0.0*
"""

    output_path = Path(__file__).parent / "api-reference.md"
    output_path.write_text(doc, encoding="utf-8")
    print(f"Generated: {output_path}")
    return doc


def generate_pdf(doc: str):
    """Generate PDF from markdown using reportlab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate,
            Paragraph,
            Spacer,
            Table,
            TableStyle,
            PageBreak,
        )
        from reportlab.lib import colors

        output_path = Path(__file__).parent / "api-reference.pdf"
        pdf = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch,
        )

        styles = getSampleStyleSheet()
        story = []

        for line in doc.split("\n"):
            if line.startswith("# "):
                story.append(Paragraph(line[2:], styles["Title"]))
                story.append(Spacer(1, 12))
            elif line.startswith("## "):
                story.append(Paragraph(line[3:], styles["Heading2"]))
                story.append(Spacer(1, 8))
            elif line.startswith("### "):
                story.append(Paragraph(line[4:], styles["Heading3"]))
                story.append(Spacer(1, 6))
            elif line.startswith("|"):
                continue
            elif line.startswith("- "):
                story.append(Paragraph(f"\u2022 {line[2:]}", styles["Normal"]))
            elif line.strip():
                story.append(Paragraph(line, styles["Normal"]))
                story.append(Spacer(1, 4))

        pdf.build(story)
        print(f"Generated: {output_path}")
    except ImportError:
        print("Warning: reportlab not installed. PDF generation skipped.")
        print("Install with: pip install reportlab")


if __name__ == "__main__":
    fmt = sys.argv[1] if len(sys.argv) > 1 else "md"
    doc = generate_markdown_docs()
    if fmt in ["pdf", "both"]:
        generate_pdf(doc)
