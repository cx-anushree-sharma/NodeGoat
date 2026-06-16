================================================================================
CHECKMARX ONE CI/CD INTEGRATION
================================================================================

A cross-platform Python script that integrates Checkmarx One into a CI build:
  - Pulls source code (done by the CI tool, e.g. GitHub Actions checkout)
  - Initiates a SAST scan via the official Checkmarx 'cx' CLI
  - Waits for the scan to finish (CLI default behavior)
  - Generates a JSON report
  - Parses the report and produces a summary by severity and vulnerability
  - Sends an HTML email to a configurable recipient list
  - Optionally fails the build if Critical/High findings are detected

================================================================================
1. CONTENTS OF THIS PACKAGE
================================================================================

  checkmarx_scan.py                       Main Python script (orchestrates scan + email)
  validate_config.py                      Pre-flight config validator (custom executable)
  .github/workflows/checkmarx-scan.yml    GitHub Actions workflow (multi-platform)
  config.example.json                     Local-run configuration template
  requirements.txt                        Python deps (none external - stdlib only)
  .gitignore                              Prevents committing secrets/reports
  ReadMe.txt                              This file


================================================================================
2. PREREQUISITES
================================================================================

  - Python 3.7 or newer
  - The Checkmarx CLI ('cx') installed and on the system PATH
    Download: https://github.com/Checkmarx/ast-cli/releases
    Docs:     https://docs.checkmarx.com/en/34965-68620-checkmarx-one-cli-tool.html

  - A Checkmarx One account with:
      * API Key
      * Tenant name
      * A group you are a member of

  - SMTP credentials to send mail (Gmail App Password recommended)


================================================================================
3. USAGE - OPTION A: GITHUB ACTIONS (Recommended)
================================================================================

This is the production-style flow the assignment asks for: the CI utility runs
the scan automatically when code is pushed.

  Step 1: Push the project files to your GitHub repository.
          The workflow file MUST be at:
            .github/workflows/checkmarx-scan.yml

  Step 2: Add GitHub Secrets (Settings > Secrets and variables > Actions):

            CX_BASE_URI       = https://eu.ast.checkmarx.net
            CX_TENANT         = test_naftali
            CX_APIKEY         = <your Checkmarx API key>
            CX_GROUP          = Anushree

            SMTP_SERVER       = smtp.gmail.com
            SMTP_PORT         = 587
            SMTP_USER         = sharma.anu2363@gmail.com
            SMTP_PASSWORD     = <your Gmail App Password>
            EMAIL_RECIPIENTS  = sharma.anu2363@gmail.com

          (Multiple recipients are supported: comma-separated.)

  Step 3: Push a commit OR trigger the workflow manually:
            GitHub > Actions > "Checkmarx One Security Scan" > Run workflow

  Step 4: Watch the workflow execute on Ubuntu, Windows, and macOS in parallel.
          Each run:
            - Installs Python and the cx CLI
            - Runs the scan
            - Sends the email
            - Uploads the JSON report as a build artifact
            - Fails the job if Critical/High findings exist


================================================================================
4. USAGE - OPTION B: LOCAL RUN (For testing without CI)
================================================================================

  Step 1: Install the cx CLI on your machine and ensure 'cx version' works.

  Step 2: Copy the config template and fill in your values:

            cp config.example.json config.json
            # Edit config.json - add API key, group, SMTP password, etc.

  Step 3: Run the script:

            python checkmarx_scan.py

          The script will:
            - Read config.json
            - Run 'cx scan create' against the current directory
            - Parse the report
            - Send the email
            - Exit non-zero if Critical/High findings exist

  Optional flags:
    --config <path>     Use a different config file
    --skip-email        Run scan and parse report, but don't send email
                        (useful for testing)
================================================================================
5. PRE-FLIGHT VALIDATION (validate_config.py)
================================================================================

The solution includes a separate Python executable, validate_config.py, that
runs BEFORE the main scan to fail fast on configuration errors. It is invoked
automatically by the GitHub Actions workflow, and can also be run standalone.

Why this exists:
  A full Checkmarx scan takes 5-15 minutes. If a credential is wrong, you'd
  normally only discover that after waiting for the scan to finish. The
  validator catches misconfigurations in under 30 seconds, saving CI minutes
  and developer time.

What it checks (6 checks total):
  [1] All required environment variables / config keys are set
  [2] The 'cx' CLI is installed and on PATH
  [3] Checkmarx authentication works (validates apikey + tenant + base-uri)
  [4] SMTP credentials are accepted by the email server (no email sent)
  [5] Recipient email addresses are well-formed
  [6] Source path exists and is readable

Exit codes:
  0 - All checks passed; scan can proceed
  1 - One or more checks failed; scan should NOT proceed

Standalone usage (useful for setup/troubleshooting):
  python validate_config.py                  # use config.json + env vars
  python validate_config.py --config X.json  # use a different config
  python validate_config.py --quiet          # only print failures

In the GitHub Actions workflow, this runs as the step
"Validate configuration (pre-flight check)" — if it fails, the scan step is
skipped and the workflow fails immediately with a clear error.

Design note on "custom additional executables":
  The assignment permits custom additional executables in C++, Java, Go, or
  Python. validate_config.py is implemented in Python (one of the approved
  languages) and is a genuinely useful separate executable that can be run
  independently of the main scan script. This avoids unnecessary complexity
  (no JVM or C++ toolchain dependencies) while still demonstrating the
  modularity that the requirement enables.

================================================================================
6. CONFIGURATION REFERENCE
================================================================================

All settings can be provided via environment variables (preferred for CI)
or via config.json (preferred for local). Environment variables take precedence.

  CHECKMARX
    CX_BASE_URI         Checkmarx One server URL (default: https://eu.ast.checkmarx.net)
    CX_TENANT           Tenant name (REQUIRED)
    CX_APIKEY           API key (REQUIRED)
    CX_PROJECT_NAME     Project name shown in CxOne (default: CI_Project)
    CX_GROUP            Group name to assign project to (Task 3d)
    CX_BRANCH           Branch being scanned (default: main)
    CX_SCAN_TYPES       Scan engines: sast, sca, iac-security (default: sast)
    CX_SOURCE           Path to source code (default: .)

  EMAIL
    SMTP_SERVER         SMTP host (default: smtp.gmail.com)
    SMTP_PORT           SMTP port (default: 587)
    SMTP_USER           Login username (REQUIRED)
    SMTP_PASSWORD       Login password / Gmail App Password (REQUIRED)
    EMAIL_FROM          From address (default: same as SMTP_USER)
    EMAIL_FROM_NAME     Display name (default: "Checkmarx CI Pipeline")
    EMAIL_RECIPIENTS    Comma-separated recipient list (REQUIRED)

  BEHAVIOR
    FAIL_ON_SEVERITY    Comma-separated severities that fail the build
                        (default: critical,high)
    OUTPUT_PATH         Where to write the JSON report (default: ./cx_reports)
    OUTPUT_NAME         Report filename without extension (default: checkmarx_report)


================================================================================
7. HOW THE EMAIL SUMMARY IS GENERATED
================================================================================

  - Results per severity:
      Counts findings in each bucket (Critical, High, Medium, Low, Info)
      and displays them with color-coded indicators.

  - Results per vulnerability:
      Groups findings by their queryName (or equivalent field) and shows
      the top 20 most-frequent vulnerability types in a sortable list.

  - Email format:
      Multipart message with HTML body (primary) and plain-text fallback.
      Subject line carries a quick severity snapshot, e.g.:
        [Checkmarx] Vulnerable_CI_Pipeline - C:2 H:5 M:12 L:8


================================================================================
8. HOW TO GET A GMAIL APP PASSWORD
================================================================================

  1. Enable 2-Step Verification on your Google account:
       https://myaccount.google.com/signinoptions/two-step-verification

  2. Create an App Password:
       https://myaccount.google.com/apppasswords

  3. The 16-character password (e.g. "abcd efgh ijkl mnop") is what goes
     into SMTP_PASSWORD - NOT your regular Gmail password.

  4. App Passwords work with smtp.gmail.com:587 + STARTTLS.


================================================================================
9. CROSS-PLATFORM SUPPORT
================================================================================

  The Python script is OS-agnostic:
    - Uses pathlib (no hardcoded path separators)
    - Uses subprocess (works on Windows, Linux, macOS)
    - Only depends on Python standard library

  The GitHub Actions workflow uses a matrix strategy that runs the scan
  on Ubuntu, Windows, and macOS in parallel, proving cross-platform
  compatibility.


================================================================================
10. ALTERNATIVE APPROACH (NOTE)
================================================================================

  Checkmarx One also provides a built-in Email Feedback App
  (Integrations > Feedback Apps > Email) that can send scan summary
  notifications directly from the platform without any script.

  However, this assignment explicitly requires:
    (a) A CI-utility-driven build flow,
    (b) A custom script,
    (c) Self-implemented JSON analysis,
    (d) An email pipeline you control.

  These map to writing a script that calls the CLI and handles email
  itself, which is what this solution does. The Feedback App would
  bypass the CLI and the script entirely.


================================================================================
11. TROUBLESHOOTING
================================================================================

  Problem: "cx CLI not found on PATH"
  Fix:     Install from https://github.com/Checkmarx/ast-cli/releases
           and add the binary's folder to PATH. Test with: cx version

  Problem: "SMTP auth failed" with Gmail
  Fix:     Use a Gmail App Password, not your account password.
           Ensure 2-Step Verification is enabled first.

  Problem: Workflow says "Resource not accessible by integration"
  Fix:     The GitHub Secrets are missing or misnamed. Check the secret
           names match exactly (case-sensitive).

  Problem: Scan succeeds but report file not found
  Fix:     Confirm OUTPUT_PATH is writable and not blocked by .gitignore.
           Check the script's stdout for the exact path it tried to read.

  Problem: Wrong severity counts in the email
  Fix:     The CLI's JSON format varies slightly across versions. The
           parser falls back through several known field names. If your
           CLI version produces an unfamiliar structure, share a sample
           report and the parser can be extended in parse_report().


================================================================================
12. REFERENCES
================================================================================

  Checkmarx CLI:       https://docs.checkmarx.com/en/34965-68620-checkmarx-one-cli-tool.html
  CLI Quick Start:     https://checkmarx.com/resource/documents/en/34965-68621-checkmarx-one-cli-quick-start-guide.html
  CLI Releases:        https://github.com/Checkmarx/ast-cli/releases
  Checkmarx One:       https://eu.ast.checkmarx.net
  Gmail App Passwords: https://myaccount.google.com/apppasswords

================================================================================
