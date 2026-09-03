#!/usr/bin/env python3
"""
Checkmarx CI - Pre-flight Configuration Validator
===================================================

A standalone validator that runs BEFORE the main scan to catch
configuration errors in seconds instead of after a 10-15 minute scan.

Checks performed:
  1. Required environment variables / config keys are set
  2. The 'cx' CLI is installed and on PATH
  3. Checkmarx authentication works (validates API key + tenant + URI)
  4. SMTP credentials work (TLS handshake + login, but no email sent)
  5. Recipient email addresses are well-formed
  6. Local source path exists and is readable

Exit codes:
  0 - All checks passed; safe to proceed with scan
  1 - One or more checks failed; do NOT run the scan

Usage:
  python validate_config.py                  # uses config.json + env vars
  python validate_config.py --config X.json  # uses custom config
  python validate_config.py --quiet          # only print failures

Credentials (CX_APIKEY, SMTP_PASSWORD) are read from environment variables
ONLY and are never loaded from the config file. Put non-secret settings in
config.json; supply secrets through your CI secret store or shell environment.

Designed to be called standalone OR as a pre-step in CI.
"""

import os
import sys
import re
import json
import smtplib
import argparse
import subprocess
from pathlib import Path


# ANSI colors (degrade gracefully on Windows without colorama)
def _supports_color():
    return sys.stdout.isatty() and os.name != 'nt' or 'WT_SESSION' in os.environ


_USE_COLOR = _supports_color()
GREEN  = '\033[92m' if _USE_COLOR else ''
RED    = '\033[91m' if _USE_COLOR else ''
YELLOW = '\033[93m' if _USE_COLOR else ''
RESET  = '\033[0m'  if _USE_COLOR else ''


def ok(msg):
    print(f"  {GREEN}[OK]{RESET}    {msg}")


def fail(msg):
    print(f"  {RED}[FAIL]{RESET}  {msg}")


def warn(msg):
    print(f"  {YELLOW}[WARN]{RESET}  {msg}")


SECRET_ENV_KEYS = ('CX_APIKEY', 'SMTP_PASSWORD')

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
            warn(f"{env_key} found in the config file and IGNORED. "
                 f"Remove it from the file and rotate the credential, "
                 f"then set the {env_key} environment variable instead.")


# ---------------------------------------------------------------------------
# Config loading (same logic as main script for consistency)
# ---------------------------------------------------------------------------

def load_config(config_path):
    cfg = {}

    if config_path:
        # Containment check. os.path.realpath() collapses '..' segments and
        # resolves symlinks; the startswith() comparison then asserts the
        # result is inside the working directory. Normalizing alone is not a
        # validation: '../../etc/passwd' normalizes to a clean absolute path.
        # The trailing separator prevents a sibling directory whose name
        # merely starts with the base name (e.g. '/srv/appEVIL' vs '/srv/app')
        # from passing the prefix test.
        base_dir = os.path.realpath(os.getcwd())
        resolved_config_path = os.path.realpath(os.path.abspath(str(config_path)))

        if resolved_config_path == base_dir or resolved_config_path.startswith(base_dir + os.sep):
            if os.path.isfile(resolved_config_path):
                with open(resolved_config_path, "r") as f:
                    cfg = json.load(f)
                _warn_on_secrets_in_file(cfg)
        else:
            fail(f"Config path resolves outside the allowed base directory: {resolved_config_path}")
            sys.exit(2)

    def get(env_key, json_path, default=None):
        if os.environ.get(env_key):
            return os.environ[env_key]
        cur = cfg
        for k in json_path.split('.'):
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                return default
        return cur if cur != "" else default

    return {
        'cx_base_uri':   get('CX_BASE_URI',   'checkmarx.base_uri', 'https://eu.ast.checkmarx.net'),
        'cx_tenant':     get('CX_TENANT',     'checkmarx.tenant'),
        'cx_apikey':     _get_secret('CX_APIKEY'),
        'cx_group':      get('CX_GROUP',      'checkmarx.group'),
        'cx_source':     get('CX_SOURCE',     'checkmarx.source', '.'),
        'smtp_server':   get('SMTP_SERVER',   'email.smtp_server', 'smtp.gmail.com'),
        'smtp_port':     int(get('SMTP_PORT', 'email.smtp_port', '587')),
        'smtp_user':     get('SMTP_USER',     'email.smtp_user'),
        'smtp_password': _get_secret('SMTP_PASSWORD'),
        'email_to':      get('EMAIL_RECIPIENTS', 'email.recipients'),
    }


# ---------------------------------------------------------------------------
# Individual checks - each returns True (pass) or False (fail)
# ---------------------------------------------------------------------------

def check_required_fields(cfg):
    print("\n[1/6] Required configuration fields")
    # Maps internal config keys to the ENVIRONMENT VARIABLE NAMES that supply
    # them. The right-hand strings are variable names used for error messages,
    # not credential values.
    required = (
        ('cx_apikey',     'CX_APIKEY'),
        ('cx_tenant',     'CX_TENANT'),
        ('smtp_user',     'SMTP_USER'),
        ('smtp_password', 'SMTP_PASSWORD'),
        ('email_to',      'EMAIL_RECIPIENTS'),
    )
    passed = True
    for key, env_name in required:
        if cfg.get(key):
            ok(f"{env_name} is set")
        else:
            fail(f"{env_name} is NOT set")
            passed = False
    return passed


def check_cx_cli_installed():
    print("\n[2/6] Checkmarx CLI ('cx') installed and on PATH")
    try:
        result = subprocess.run(['cx', 'version'],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip().splitlines()[0] if result.stdout else 'unknown'
            ok(f"cx CLI found ({version})")
            return True
        else:
            fail(f"cx CLI returned non-zero exit code {result.returncode}")
            return False
    except FileNotFoundError:
        fail("cx CLI not found on PATH. Install from:")
        fail("https://github.com/Checkmarx/ast-cli/releases")
        return False
    except subprocess.TimeoutExpired:
        fail("cx version timed out (10s)")
        return False


def check_cx_authentication(cfg):
    """
    Validate Checkmarx credentials by invoking 'cx auth validate'.

    Security note: credentials are passed to the child process through the
    environment rather than as command-line arguments. The argv list is fully
    static, so no configuration-derived data reaches the process-spawning
    call, and secrets are not exposed to other local users through process
    listings such as 'ps' or Task Manager.
    """
    print("\n[3/6] Checkmarx authentication (API key + tenant + URI)")
    if not cfg.get('cx_apikey') or not cfg.get('cx_tenant'):
        fail("Missing CX_APIKEY or CX_TENANT (cannot test auth)")
        return False

    # Static command - contains no configuration-derived values.
    cmd = ['cx', 'auth', 'validate']

    # Credentials are supplied via the child process environment instead.
    env = os.environ.copy()
    env['CX_APIKEY'] = str(cfg['cx_apikey'])
    env['CX_BASE_URI'] = str(cfg['cx_base_uri'])
    env['CX_TENANT'] = str(cfg['cx_tenant'])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=30, env=env)
        if result.returncode == 0:
            ok(f"Authenticated against {cfg['cx_base_uri']} (tenant: {cfg['cx_tenant']})")
            return True
        else:
            fail(f"Authentication failed: {result.stderr.strip()[:200]}")
            return False
    except FileNotFoundError:
        fail("cx CLI not found on PATH (cannot test auth)")
        return False
    except subprocess.TimeoutExpired:
        fail("Auth check timed out (30s) - network or server issue?")
        return False
    except Exception as e:
        fail(f"Auth check error: {e}")
        return False


def check_smtp_credentials(cfg):
    print("\n[4/6] SMTP credentials (TLS + login, no email sent)")
    if not all([cfg.get('smtp_server'), cfg.get('smtp_user'), cfg.get('smtp_password')]):
        fail("Missing SMTP_SERVER, SMTP_USER, or SMTP_PASSWORD")
        return False

    try:
        with smtplib.SMTP(cfg['smtp_server'], cfg['smtp_port'], timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.ehlo()
            s.login(cfg['smtp_user'], cfg['smtp_password'])
        ok(f"SMTP login succeeded ({cfg['smtp_user']} @ {cfg['smtp_server']}:{cfg['smtp_port']})")
        return True
    except smtplib.SMTPAuthenticationError as e:
        fail(f"SMTP auth rejected by server: {str(e)[:200]}")
        fail("Tip: for Gmail, use an App Password (not your account password).")
        return False
    except (smtplib.SMTPException, OSError) as e:
        fail(f"SMTP connection failed: {e}")
        return False


def check_recipient_format(cfg):
    print("\n[5/6] Recipient email addresses are well-formed")
    raw = cfg.get('email_to', '') or ''
    recipients = [e.strip() for e in raw.split(',') if e.strip()]
    if not recipients:
        fail("EMAIL_RECIPIENTS is empty")
        return False

    # Simple but practical email regex
    pattern = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
    bad = [r for r in recipients if not pattern.match(r)]
    if bad:
        for b in bad:
            fail(f"Invalid email format: {b}")
        return False
    ok(f"All {len(recipients)} recipient(s) look valid: {', '.join(recipients)}")
    return True


def check_source_path(cfg):
    """
    Confirm the configured source directory exists and is readable.

    The configured path is resolved with os.path.realpath() (which collapses
    '..' segments and follows symlinks) and then asserted to be inside the
    working directory before any filesystem operation is performed. If the
    path escapes the base directory the function fails closed and returns
    without touching the filesystem.
    """
    print("\n[6/6] Source path exists and is readable")

    base_dir = os.path.realpath(os.getcwd())
    src_path = os.path.realpath(os.path.abspath(str(cfg.get('cx_source', '.'))))

    # Containment check expressed positively: EVERY filesystem operation on
    # src_path happens inside this condition body, so the path cannot reach
    # os.access(), os.stat() or a directory walk unless it has been confirmed
    # to resolve inside base_dir. See the note in load_config() on why the
    # trailing separator matters and why normalization alone is not
    # validation.
    if src_path == base_dir or src_path.startswith(base_dir + os.sep):
        if not os.path.exists(src_path):
            fail(f"Source path does not exist: {src_path}")
            return False
        if not os.access(src_path, os.R_OK):
            fail(f"Source path is not readable: {src_path}")
            return False
        # Count code-like files quickly to confirm there's something to scan
        sample = list(Path(src_path).rglob('*'))[:1000]
        file_count = sum(1 for p in sample if p.is_file())
        ok(f"Source path readable ({file_count}+ files at {src_path})")
        return True

    fail(f"Source path resolves outside the allowed base directory: {src_path}")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Checkmarx CI pre-flight configuration validator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='Run this BEFORE checkmarx_scan.py to fail fast on misconfig.'
    )
    parser.add_argument('--config', default='config.json',
                        help='Path to config file (default: config.json)')
    parser.add_argument('--quiet', action='store_true',
                        help='Only print failures, not successes')
    args = parser.parse_args()

    if not args.quiet:
        print("=" * 70)
        print("CHECKMARX CI - PRE-FLIGHT CONFIGURATION VALIDATOR")
        print("=" * 70)

    cfg = load_config(args.config)

    checks = [
        check_required_fields(cfg),
        check_cx_cli_installed(),
        check_cx_authentication(cfg),
        check_smtp_credentials(cfg),
        check_recipient_format(cfg),
        check_source_path(cfg),
    ]

    print("\n" + "=" * 70)
    passed = sum(1 for c in checks if c)
    total = len(checks)
    if all(checks):
        print(f"{GREEN}RESULT: All {total}/{total} checks passed. Safe to run the scan.{RESET}")
        sys.exit(0)
    else:
        print(f"{RED}RESULT: {passed}/{total} checks passed. Fix the failures above before running the scan.{RESET}")
        sys.exit(1)


if __name__ == '__main__':
    main()