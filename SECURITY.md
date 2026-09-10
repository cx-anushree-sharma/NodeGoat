# Security Policy

## About this repository

This is a personal fork of [OWASP/NodeGoat](https://github.com/OWASP/NodeGoat),
used to trigger Checkmarx One SCA/SCS scans and practice vulnerability triage.
It is not the upstream project and does not accept external contributions or
handle a public disclosure process.

## NodeGoat's intentional vulnerabilities

NodeGoat is a deliberately vulnerable teaching application built to
demonstrate the OWASP Top 10. The vulnerabilities present in the application
code itself (SQL/NoSQL injection, XSS, insecure session handling, etc.) are
**intentional and expected** - please do not report them here or upstream.

## Reporting an issue with this fork specifically

If you find an actual accidental problem in this fork's own tooling (for
example, in `validate_config.py`, the CI workflows under `.github/workflows/`,
or the fuzzing harness under `fuzz/`) that is unrelated to NodeGoat's
intentional teaching vulnerabilities, please open an issue on this repository.

## Reporting an issue with upstream NodeGoat

For anything concerning the upstream project itself, use the OWASP/NodeGoat
repository's [issue tracker](https://github.com/OWASP/NodeGoat/issues) rather
than this fork.
