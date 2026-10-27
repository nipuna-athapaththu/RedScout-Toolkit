"""PDF report using WeasyPrint. Falls back to HTML if unavailable."""
from pathlib import Path
from .cvss import severity
from .mitre_mapping import map_technique

HTML_TEMPLATE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
@page {{ size: A4; margin: 2cm; }}
body {{ font-family: Helvetica, Arial, sans-serif; color:#111; }}
h1 {{ color:#0b3d91; border-bottom:3px solid #0b3d91; padding-bottom:8px; }}
h2 {{ color:#0b3d91; margin-top:24px; }}
.badge {{ display:inline-block; padding:3px 8px; border-radius:4px; color:#fff; font-size:12px; }}
.critical {{ background:#b30000; }} .high {{ background:#e34a00; }}
.medium {{ background:#d9a300; }} .low {{ background:#4a8f00; }}
.info {{ background:#4a8f00; }}
table {{ border-collapse: collapse; width:100%; margin:12px 0; }}
th,td {{ border:1px solid #ccc; padding:6px; text-align:left; font-size:12px; }}
th {{ background:#f0f4fa; }}
.disclaimer {{ background:#fff4f4; border-left:4px solid #b30000; padding:10px; margin:10px 0; }}
.mitre {{ font-family: monospace; font-size:11px; color:#555; }}
</style></head><body>
<h1>RedScout Penetration Test Report</h1>
<div class="disclaimer">
⚠️ <b>Authorized testing only.</b> This document is confidential.
Test performed under signed scope authorization.
</div>
<h2>Executive Summary</h2>
<p>{exec_summary}</p>
<h2>Graph Summary</h2>
<p>Hosts: <b>{hosts}</b> | Services: <b>{services}</b> | Vulnerabilities: <b>{vulns}</b></p>
<h2>Findings</h2>
{findings_table}
<h2>MITRE ATT&CK Coverage</h2>
{mitre_table}
</body></html>
"""

def generate(path: str, summary: dict, findings: list, exec_summary: str = "") -> str:
    # 1. Findings Table එක 
    rows = ""
    for f in findings:
        sev = f.get("severity", "Info").lower()
        
        f_name = f.get('name') or f.get('template') or f.get('service') or f.get('subdomain') or f.get('type') or "Information Gathered"
        f_target = f.get('url') or f.get('port') or f.get('ip') or f.get('value') or "N/A"
        f_rem = f.get('remediation', 'Review and verify')

        badge_class = sev if sev in ["critical", "high", "medium", "low"] else "info"

        rows += (
            f"<tr><td>{f_name}</td>"
            f"<td><span class='badge {badge_class}'>{sev.capitalize()}</span></td>"
            f"<td>{f_target}</td>"
            f"<td>{f_rem}</td></tr>"
        )
    if not rows:
        rows = "<tr><td colspan='4'>No findings recorded.</td></tr>"

    # 2. MITRE Table එක හදමු
    mitre_rows = ""
    for tech in summary.get("techniques", []):
        m = map_technique(tech)
        mitre_rows += (
            f"<tr><td>{tech}</td><td>{m['tactic']}</td>"
            f"<td class='mitre'>{m['technique_id']} - {m['technique']}</td></tr>"
        )
    if not mitre_rows:
        mitre_rows = "<tr><td colspan='3'>No techniques mapped.</td></tr>"

    # 3. HTML එකට දත්ත දාමු
    html = HTML_TEMPLATE.format(
        exec_summary=exec_summary or "See findings below.",
        hosts=summary.get("hosts", 0),
        services=summary.get("services", 0),
        vulns=summary.get("vulns", 0),
        findings_table=f"<table><tr><th>Finding</th><th>Severity</th><th>Target</th><th>Remediation</th></tr>{rows}</table>",
        mitre_table=f"<table><tr><th>Technique</th><th>Tactic</th><th>ATT&CK</th></tr>{mitre_rows}</table>",
    )

    # 4. File එක Save කරමු (Folder එක නැත්නම් හදනවා)
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    html_path = out_path.with_suffix(".html")
    html_path.write_text(html, encoding="utf-8")

    try:
        from weasyprint import HTML
        pdf_path = out_path.with_suffix(".pdf")
        HTML(string=html).write_pdf(str(pdf_path))
        return str(pdf_path)
    except ImportError:
        return str(html_path)
    except Exception:
        return str(html_path)