#!/usr/bin/env python3
"""
Checkmarx One CI/CD Integration Script
=======================================

This script orchestrates a Checkmarx One security scan in a CI pipeline:
  1. Uses Checkmarx CLI ('cx') to initiate a scan against source code already
     checked out by the CI tool.
  2. Waits for scan completion (CLI default behavior - no --async flag).
  3. CLI generates a JSON report directly into the output path.
  4. Parses the JSON report to summarize findings by severity and vulnerability.
  5. Sends an HTML email to a configured recipient list via SMTP.
  6. Exits with non-zero code if Critical or High findings exist (build gating).

Configuration is read from environment variables (suitable for CI/CD secrets)
with fallback to a config.json file for local runs.

Cross-platform: Works on Windows, Linux, macOS (requires Python 3.7+ and 'cx' CLI on PATH).
"""

import os
import re
import sys
import json
import smtplib
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr


# ---------------------------------------------------------------------------
# Allow-lists and validation helpers for values passed to the 'cx' CLI
# ---------------------------------------------------------------------------

# Scan types the CLI accepts. The value sent to the CLI is rebuilt from THIS
# tuple, so no configuration-derived string is ever forwarded to the process.
ALLOWED_SCAN_TYPES = ('sast', 'sca', 'iac-security', 'api-security', 'containers')

# Conservative charset for free-text CLI arguments (project/branch/output names).
_SAFE_NAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._/-]{0,127}$')


def _safe_name(value, field_name):
    """
    Validate a free-text value that must be passed as a CLI argument.

    Rejects empty values, values beginning with '-' (which the CLI would parse
    as a flag rather than a value - argument injection), and anything outside a
    conservative allow-listed charset and length.
    """
    text = str(value)
    if not text:
        raise ValueError(f"{field_name} is empty")
    if text.startswith('-'):
        raise ValueError(f"{field_name} must not start with '-'")
    if not _SAFE_NAME_RE.match(text):
        raise ValueError(f"{field_name} contains disallowed characters: {text!r}")
    return text


def _contained_path(value, field_name, base=None):
    """
    Resolve a path and confirm it stays within an allowed base directory.

    Normalizing a path is NOT enough on its own: '../../etc/passwd' normalizes
    to a perfectly clean absolute path. Containment must be checked explicitly.
    """
    base_dir = Path(base or os.getcwd()).resolve()
    candidate = Path(str(value)).expanduser()
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    resolved = candidate.resolve()
    try:
        resolved.relative_to(base_dir)
    except ValueError:
        raise ValueError(
            f"{field_name} resolves outside the allowed base directory "
            f"({resolved} is not under {base_dir})"
        )
    return resolved


def _resolve_scan_types(requested_value):
    """
    Map the requested scan types onto the allow-list.

    The returned string is assembled from ALLOWED_SCAN_TYPES constants; the
    configured value is only used for membership testing, so no untrusted data
    flows into the returned value.
    """
    requested = {t.strip().lower() for t in str(requested_value).split(',') if t.strip()}
    unknown = requested - set(ALLOWED_SCAN_TYPES)
    if unknown:
        raise ValueError(f"unsupported scan type(s): {', '.join(sorted(unknown))}")
    selected = [t for t in ALLOWED_SCAN_TYPES if t in requested]
    if not selected:
        raise ValueError("no valid scan types configured")
    return ','.join(selected)


# Config-file locations that must NOT hold credentials. Used only to emit a
# warning; these values are never read into the returned configuration.
_SECRET_JSON_PATHS = {
    'CX_APIKEY': 'checkmarx.apikey',
    'SMTP_PASSWORD': 'email.smtp_password',
}


def _get_secret(env_key):
    """
    Resolve a credential from the process environment ONLY.

    Secrets are deliberately never read from the config file: a plaintext
    credential on disk can be read by any local user, is easy to commit to
    version control by accident, and outlives the process that uses it. In CI
    these come from the pipeline's secret store; locally, export them in your
    shell.

    This function reads nothing but os.environ, so no file-sourced data can
    reach a credential field.
    """
    return os.environ.get(env_key)


def _warn_on_secrets_in_file(raw_config):
    """
    Warn if the config file contains credentials.

    Deliberately returns nothing: this inspects file-sourced data purely to
    print an operator warning, and its result never feeds the configuration.
    """
    for env_key, json_path in _SECRET_JSON_PATHS.items():
        cur = raw_config
        for k in json_path.split('.'):
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                cur = None
                break
        if cur:
            print(f"[WARN] {env_key} found in the config file and IGNORED. "
                  f"Remove it from the file and rotate the credential, "
                  f"then set the {env_key} environment variable instead.")


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_config(config_path=None):
    """
    Load configuration. Environment variables take precedence over config.json.
    This makes the script work seamlessly in CI (env vars / GitHub Secrets)
    and locally (config.json).
    """
    config = {}

    # Try loading config.json first (for local runs)
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            config = json.load(f)
        print(f"[INFO] Loaded config from {config_path}")
        _warn_on_secrets_in_file(config)

    # Helper to fetch with env override
    def get(env_key, json_path, default=None):
        if os.environ.get(env_key):
            return os.environ[env_key]
        cur = config
        for k in json_path.split('.'):
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                return default
        return cur if cur != "" else default

    return {
        # Checkmarx
        'cx_base_uri':    get('CX_BASE_URI', 'checkmarx.base_uri', 'https://eu.ast.checkmarx.net'),
        'cx_tenant':      get('CX_TENANT', 'checkmarx.tenant'),
        'cx_apikey':      _get_secret('CX_APIKEY'),
        'cx_project':     get('CX_PROJECT_NAME', 'checkmarx.project_name', 'CI_Project'),
        'cx_group':       get('CX_GROUP', 'checkmarx.group'),
        'cx_branch':      get('CX_BRANCH', 'checkmarx.branch', 'main'),
        'cx_scan_types':  get('CX_SCAN_TYPES', 'checkmarx.scan_types', 'sast'),
        'cx_source':      get('CX_SOURCE', 'checkmarx.source', '.'),
        # Email
        'smtp_server':    get('SMTP_SERVER', 'email.smtp_server', 'smtp.gmail.com'),
        'smtp_port':      int(get('SMTP_PORT', 'email.smtp_port', '587')),
        'smtp_user':      get('SMTP_USER', 'email.smtp_user'),
        'smtp_password':  _get_secret('SMTP_PASSWORD'),
        'email_from':     get('EMAIL_FROM', 'email.from_address'),
        'email_from_name': get('EMAIL_FROM_NAME', 'email.from_name', 'Checkmarx CI Pipeline'),
        'email_to':       get('EMAIL_RECIPIENTS', 'email.recipients'),
        # Behavior
        'fail_on':        get('FAIL_ON_SEVERITY', 'behavior.fail_on_severity', 'critical,high'),
        'output_path':    get('OUTPUT_PATH', 'behavior.output_path', './cx_reports'),
        'output_name':    get('OUTPUT_NAME', 'behavior.output_name', 'checkmarx_report'),
    }


def validate_config(cfg):
    """Ensure required fields are present. Fail fast with clear messages."""
    required = {
        'cx_apikey':     'Checkmarx API key (set CX_APIKEY)',
        'cx_tenant':     'Checkmarx tenant (set CX_TENANT)',
        'smtp_user':     'SMTP username (set SMTP_USER)',
        'smtp_password': 'SMTP password (set SMTP_PASSWORD)',
        'email_to':      'Email recipients (set EMAIL_RECIPIENTS, comma-separated)',
    }
    missing = [v for k, v in required.items() if not cfg.get(k)]
    if missing:
        print("[ERROR] Missing required configuration:")
        for m in missing:
            print(f"   - {m}")
        sys.exit(2)

    if not cfg.get('email_from'):
        cfg['email_from'] = cfg['smtp_user']


# ---------------------------------------------------------------------------
# Step 1: Run Checkmarx scan via CLI
# ---------------------------------------------------------------------------

def run_scan(cfg):
    """
    Execute 'cx scan create' with verified flags.
    The CLI:
      - Waits for scan completion by default (we are NOT passing --async)
      - Generates a JSON report directly via --report-format json
      - Writes report to <output-path>/<output-name>.json

    Security notes:
      - Credentials (API key, tenant, base URI) are passed through the child
        process environment rather than argv. This keeps secrets out of local
        process listings ('ps', Task Manager) and out of the command line.
      - --scan-types is rebuilt from the ALLOWED_SCAN_TYPES constants.
      - Remaining arguments are allow-list validated, and path arguments are
        checked for containment within the working directory.
      - subprocess is invoked with a list and shell=False (the default), so no
        shell interprets the arguments.
    """
    print("\n" + "="*70)
    print("STEP 1: Initiating Checkmarx scan via CLI")
    print("="*70)

    # Validate everything that will become a command-line argument.
    try:
        project_name = _safe_name(cfg['cx_project'], 'CX_PROJECT_NAME')
        branch = _safe_name(cfg['cx_branch'], 'CX_BRANCH')
        output_name = _safe_name(cfg['output_name'], 'OUTPUT_NAME')
        scan_types = _resolve_scan_types(cfg['cx_scan_types'])
        source_dir = _contained_path(cfg['cx_source'], 'CX_SOURCE')
        output_dir = _contained_path(cfg['output_path'], 'OUTPUT_PATH')
        project_group = _safe_name(cfg['cx_group'], 'CX_GROUP') if cfg.get('cx_group') else None
    except ValueError as e:
        print(f"[ERROR] Invalid configuration: {e}")
        sys.exit(2)

    if not source_dir.is_dir():
        print(f"[ERROR] Source path is not a directory: {source_dir}")
        sys.exit(2)

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        'cx', 'scan', 'create',
        '--project-name', project_name,
        '-s', str(source_dir),
        '-b', branch,
        '--scan-types', scan_types,
        '--report-format', 'json',
        '--output-name', output_name,
        '--output-path', str(output_dir),
        '--scan-info-format', 'json',
    ]

    # Assign project to group (only if specified)
    if project_group:
        cmd += ['--project-groups', project_group]

    # Credentials go to the child process environment, never to argv.
    env = os.environ.copy()
    env['CX_APIKEY'] = str(cfg['cx_apikey'])
    env['CX_BASE_URI'] = str(cfg['cx_base_uri'])
    env['CX_TENANT'] = str(cfg['cx_tenant'])

    print(f"[INFO] Running: {' '.join(cmd)}")
    print("[INFO] Credentials supplied via environment (not shown).")
    print("[INFO] Scan in progress... (CLI waits for completion by default)")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=3600, env=env)
    except FileNotFoundError:
        print("[ERROR] 'cx' CLI not found on PATH.")
        print("[ERROR] Install from: https://docs.checkmarx.com/en/34965-68620-checkmarx-one-cli-tool.html")
        sys.exit(3)
    except subprocess.TimeoutExpired:
        print("[ERROR] Scan exceeded 1-hour timeout.")
        sys.exit(4)

    # Print CLI output (useful in CI logs)
    if result.stdout:
        print("--- cx stdout ---")
        print(result.stdout)
    if result.stderr:
        print("--- cx stderr ---")
        print(result.stderr)

    # The CLI exits non-zero on real failures; exit 0 means scan completed.
    # Note: some thresholds may also cause non-zero; we handle that ourselves
    # via Python after parsing the report.
    if result.returncode != 0:
        print(f"[WARN] CLI exited with code {result.returncode}. "
              f"This may indicate scan errors OR threshold violations. "
              f"Will still attempt to parse report if it was generated.")

    report_file = output_dir / f"{output_name}.json"
    if not report_file.exists():
        print(f"[ERROR] Expected report file not found: {report_file}")
        sys.exit(5)

    print(f"[INFO] Report generated: {report_file}")
    return report_file


# ---------------------------------------------------------------------------
# Step 2: Parse JSON report
# ---------------------------------------------------------------------------

def parse_report(report_file):
    """
    Parse the Checkmarx JSON report.

    The Checkmarx 'json' report format produces a structure that typically
    contains a top-level 'results' array with each finding having fields like
    'severity', 'queryName' (or 'vulnerabilityDetails.cweId'), etc.

    This parser is DEFENSIVE: it tries multiple known field names and falls
    back gracefully so it works across CLI versions.
    """
    print("\n" + "="*70)
    print("STEP 2: Parsing JSON report")
    print("="*70)

    with open(report_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Normalized findings list
    findings = []

    # The report may have findings under various keys depending on report format
    candidates = []
    if isinstance(data, dict):
        for key in ('results', 'scanResults', 'vulnerabilities', 'queries'):
            if key in data and isinstance(data[key], list):
                candidates = data[key]
                print(f"[INFO] Found findings under key: '{key}' ({len(candidates)} entries)")
                break

    if not candidates and isinstance(data, list):
        candidates = data
        print(f"[INFO] Report root is a list ({len(candidates)} entries)")

    for item in candidates:
        if not isinstance(item, dict):
            continue
        # Extract severity (defensive across versions)
        severity = (item.get('severity')
                    or item.get('Severity')
                    or item.get('riskLevel')
                    or 'unknown')
        severity = str(severity).strip().lower()

        # Extract vulnerability name (defensive)
        vuln_name = (item.get('queryName')
                     or item.get('vulnerabilityName')
                     or item.get('name')
                     or item.get('description')
                     or (item.get('data', {}) or {}).get('queryName')
                     or (item.get('vulnerabilityDetails', {}) or {}).get('cweId')
                     or 'Unknown Vulnerability')

        findings.append({'severity': severity, 'vulnerability': str(vuln_name)})

    # Aggregate by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'unknown': 0}
    for f in findings:
        sev = f['severity']
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            severity_counts['unknown'] += 1

    # Aggregate by vulnerability type
    vuln_counts = {}
    for f in findings:
        vuln_counts[f['vulnerability']] = vuln_counts.get(f['vulnerability'], 0) + 1

    # Extract scan metadata if available (data may be a list, so guard with isinstance)
    meta_src = data if isinstance(data, dict) else {}
    scan_summary = meta_src.get('scanSummary', {}) or {} if isinstance(meta_src, dict) else {}
    metadata = {
        'scan_id': (meta_src.get('scanID') or meta_src.get('scanId')
                    or scan_summary.get('scanId') or 'N/A'),
        'project_name': (meta_src.get('projectName')
                         or scan_summary.get('projectName') or 'N/A'),
        'created_at': (meta_src.get('createdAt') or meta_src.get('scanDate')
                       or datetime.utcnow().isoformat() + 'Z'),
    }

    summary = {
        'total': len(findings),
        'by_severity': severity_counts,
        'by_vulnerability': dict(sorted(vuln_counts.items(),
                                        key=lambda x: -x[1])),
        'metadata': metadata,
    }

    print(f"[INFO] Total findings: {summary['total']}")
    print(f"[INFO] By severity:    {summary['by_severity']}")
    print(f"[INFO] Unique vuln types: {len(summary['by_vulnerability'])}")

    return summary


# ---------------------------------------------------------------------------
# Step 3: Generate HTML email
# ---------------------------------------------------------------------------

def generate_html(summary, cfg):
    """Build a clean HTML email with severity color coding and a vuln table."""
    sev = summary['by_severity']
    meta = summary['metadata']

    sev_colors = {
        'critical': '#b91c1c', 'high': '#ea580c', 'medium': '#ca8a04',
        'low': '#16a34a', 'info': '#0284c7', 'unknown': '#6b7280'
    }

    sev_rows = ""
    for label in ('critical', 'high', 'medium', 'low', 'info'):
        count = sev.get(label, 0)
        color = sev_colors[label]
        sev_rows += f"""
          <tr>
            <td style="padding:10px 14px;border-bottom:1px solid #e5e7eb;">
              <span style="display:inline-block;width:10px;height:10px;background:{color};border-radius:50%;margin-right:8px;"></span>
              <strong>{label.capitalize()}</strong>
            </td>
            <td style="padding:10px 14px;border-bottom:1px solid #e5e7eb;text-align:right;font-weight:600;color:{color};">{count}</td>
          </tr>"""

    vuln_rows = ""
    top_vulns = list(summary['by_vulnerability'].items())[:20]
    if top_vulns:
        for name, count in top_vulns:
            safe_name = (name[:120] + '...') if len(name) > 120 else name
            safe_name = (safe_name.replace('&', '&amp;')
                         .replace('<', '&lt;').replace('>', '&gt;'))
            vuln_rows += f"""
              <tr>
                <td style="padding:8px 14px;border-bottom:1px solid #e5e7eb;">{safe_name}</td>
                <td style="padding:8px 14px;border-bottom:1px solid #e5e7eb;text-align:right;">{count}</td>
              </tr>"""
    else:
        vuln_rows = '<tr><td colspan="2" style="padding:14px;text-align:center;color:#6b7280;">No vulnerabilities found</td></tr>'

    total = summary['total']
    banner_color = '#b91c1c' if (sev['critical'] > 0 or sev['high'] > 0) else \
                   '#ca8a04' if sev['medium'] > 0 else '#16a34a'
    banner_text = 'Action Required' if (sev['critical'] > 0 or sev['high'] > 0) else \
                  'Review Recommended' if sev['medium'] > 0 else 'Clean Scan'

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:24px;background:#f3f4f6;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111827;">
  <div style="max-width:720px;margin:0 auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.1);">
    <div style="background:{banner_color};color:#fff;padding:20px 24px;">
      <div style="font-size:13px;letter-spacing:1px;opacity:0.9;">CHECKMARX ONE - SCAN REPORT</div>
      <div style="font-size:22px;font-weight:700;margin-top:4px;">{banner_text}</div>
    </div>
    <div style="padding:24px;">
      <div style="display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap;">
        <div style="flex:1;min-width:140px;background:#f9fafb;padding:14px;border-radius:6px;">
          <div style="font-size:11px;color:#6b7280;letter-spacing:0.5px;">TOTAL FINDINGS</div>
          <div style="font-size:28px;font-weight:700;margin-top:4px;">{total}</div>
        </div>
        <div style="flex:1;min-width:140px;background:#fef2f2;padding:14px;border-radius:6px;">
          <div style="font-size:11px;color:#991b1b;letter-spacing:0.5px;">CRITICAL + HIGH</div>
          <div style="font-size:28px;font-weight:700;margin-top:4px;color:#b91c1c;">{sev['critical'] + sev['high']}</div>
        </div>
      </div>

      <h3 style="font-size:14px;color:#374151;margin:24px 0 8px;text-transform:uppercase;letter-spacing:0.5px;">Results per Severity</h3>
      <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:6px;">
        {sev_rows}
      </table>

      <h3 style="font-size:14px;color:#374151;margin:24px 0 8px;text-transform:uppercase;letter-spacing:0.5px;">Results per Vulnerability (top 20)</h3>
      <table style="width:100%;border-collapse:collapse;background:#fff;border:1px solid #e5e7eb;border-radius:6px;">
        <tr style="background:#f9fafb;">
          <th style="padding:10px 14px;text-align:left;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb;">Vulnerability</th>
          <th style="padding:10px 14px;text-align:right;font-size:12px;color:#6b7280;border-bottom:1px solid #e5e7eb;">Count</th>
        </tr>
        {vuln_rows}
      </table>

      <div style="margin-top:24px;padding-top:16px;border-top:1px solid #e5e7eb;font-size:12px;color:#6b7280;line-height:1.6;">
        <strong>Project:</strong> {cfg['cx_project']}<br>
        <strong>Branch:</strong> {cfg['cx_branch']}<br>
        <strong>Group:</strong> {cfg.get('cx_group') or 'N/A'}<br>
        <strong>Scan ID:</strong> {meta['scan_id']}<br>
        <strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC<br>
        <strong>Server:</strong> <a href="{cfg['cx_base_uri']}" style="color:#0284c7;">{cfg['cx_base_uri']}</a>
      </div>
    </div>
  </div>
</body></html>"""


# ---------------------------------------------------------------------------
# Step 4: Send email
# ---------------------------------------------------------------------------

def send_email(summary, cfg):
    print("\n" + "="*70)
    print("STEP 3: Sending email summary")
    print("="*70)

    recipients = [e.strip() for e in cfg['email_to'].split(',') if e.strip()]
    if not recipients:
        print("[ERROR] No valid recipients.")
        return False

    sev = summary['by_severity']
    subject = (f"[Checkmarx] {cfg['cx_project']} - "
               f"C:{sev['critical']} H:{sev['high']} M:{sev['medium']} L:{sev['low']}")

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = formataddr((cfg['email_from_name'], cfg['email_from']))
    msg['To'] = ", ".join(recipients)

    html = generate_html(summary, cfg)
    text_fallback = (f"Checkmarx Scan Summary\n"
                     f"Project: {cfg['cx_project']}\n"
                     f"Total: {summary['total']}\n"
                     f"Critical: {sev['critical']} | High: {sev['high']} | "
                     f"Medium: {sev['medium']} | Low: {sev['low']}\n")

    msg.attach(MIMEText(text_fallback, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    try:
        print(f"[INFO] Connecting to {cfg['smtp_server']}:{cfg['smtp_port']}")
        with smtplib.SMTP(cfg['smtp_server'], cfg['smtp_port'], timeout=30) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(cfg['smtp_user'], cfg['smtp_password'])
            s.sendmail(cfg['email_from'], recipients, msg.as_string())
        print(f"[OK] Email sent to: {', '.join(recipients)}")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"[ERROR] SMTP auth failed: {e}")
        print("[ERROR] For Gmail, ensure you're using an App Password, not your account password.")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        return False


# ---------------------------------------------------------------------------
# Step 5: Decide build outcome
# ---------------------------------------------------------------------------

def evaluate_threshold(summary, fail_on):
    """Return non-zero exit code if any 'fail_on' severity has findings."""
    severities = [s.strip().lower() for s in fail_on.split(',') if s.strip()]
    sev = summary['by_severity']
    triggered = [s for s in severities if sev.get(s, 0) > 0]
    if triggered:
        print(f"\n[FAIL] Findings detected at severity: {triggered}. "
              f"Build will fail per FAIL_ON_SEVERITY policy.")
        return 1
    print(f"\n[OK] No findings at fail thresholds ({fail_on}). Build passes.")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description='Checkmarx One CI integration')
    parser.add_argument('--config', default='config.json',
                        help='Path to config file (default: config.json)')
    parser.add_argument('--skip-email', action='store_true',
                        help='Skip sending email (useful for local testing)')
    args = parser.parse_args()

    print("="*70)
    print("CHECKMARX ONE CI INTEGRATION")
    print(f"Started: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*70)

    cfg = load_config(args.config)
    validate_config(cfg)

    # Step 1: Run scan + get report
    report_file = run_scan(cfg)

    # Step 2: Parse report
    summary = parse_report(report_file)

    # Step 3: Send email
    if not args.skip_email:
        send_email(summary, cfg)
    else:
        print("[INFO] --skip-email flag set; not sending email.")

    # Step 4: Build outcome
    exit_code = evaluate_threshold(summary, cfg['fail_on'])

    print("\n" + "="*70)
    print(f"Finished: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print("="*70)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()