# Security policy

## Reporting a vulnerability

Please report security issues privately, **not** as a public GitHub issue.

- Use [GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
  on this repository, or
- email **tushsood@gmail.com**.

Include what you did, what happened, and what you expected. A proof of concept
helps. You will get an acknowledgement within 72 hours and an assessment within
a week; if a fix is warranted, the advisory credits you unless you ask otherwise.

## What is in scope

What ships is a command-line scanner, a container image that runs it, and a
browser extension with no backend of its own. There is no server and no
database. So most of the interesting failure modes are about what the tool does
with *your* data:

- **A credential reaching a place it should not.** Findings are redacted before
  they are rendered, written to a report, or sent to a model. A path that leaks
  a raw secret into stdout, a SARIF or JSON report, the extension's popup, the
  logs, or an LLM prompt is a vulnerability.
- **The scan payload escaping its sandbox.** Files are written to a temporary
  directory so bandit and eslint can run over them. A path that escapes that
  directory is a vulnerability.
- **A scanned repository changing how the scan behaves.** The repository is
  untrusted input. It may not reconfigure the scanner, cause code in it to be
  executed, or cause a request to anywhere; `.secscanignore` suppressing its own
  findings is the one influence it is allowed.
- **The model gaining authority it should not have.** Triage may only merge,
  re-rank, and annotate findings. Anything that lets a model reply create a
  finding, change a finding's file/line/rule, or delete one without accounting
  for it as a duplicate is a vulnerability.
- **The extension's network surface.** It talks to `api.github.com` and
  `api.osv.dev` and nothing else. Anything that makes it send repository
  contents, or the stored GitHub token, anywhere else is a vulnerability.

## What is not in scope

- **False positives and false negatives in the detectors.** These are quality
  bugs — please file them as normal issues, with the code that was or was not
  flagged. They matter, but they are not vulnerabilities.
- **Findings the scanner reports in *your* repository.** Those are for you to
  fix; this policy covers the scanner itself.
- Vulnerabilities in bandit, eslint-plugin-security, or OSV data. Report those
  upstream. If our integration mishandles their output, that is in scope here.

## Handling of scanned data

The scanner is designed so that running it does not create a new exposure:

- **Secrets are redacted before they leave the pipeline.** Detectors see raw
  content; a `redact_findings` stage runs before anything is reported or
  prompted, so what you get is `ghp_***…***7r8 (40 chars)`, not the token. The
  stage's position in the pipeline is asserted by a test.
- **The model never sees a credential.** Code context handed to triage is
  scrubbed with the same rules.
- **Repository contents are never transmitted.** Nothing uploads your code —
  not for telemetry, not for tracing, not to an observability backend. This was
  once a real exposure: the pipeline ran on LangGraph, whose tracing integration
  ships whole node inputs — here, the verbatim scanned source — to LangSmith
  whenever `LANGSMITH_TRACING` happens to be set in the environment, which at an
  organisation doing any LLM work it usually is. It was suppressed at the call
  site while the dependency existed, and the dependency is now gone; a test
  fails the build if anything in the package imports it again.
- **Nothing leaves your machine unless you configure it to.** With no LLM
  backend the scanner is fully local except for the OSV lookup, which sends only
  package names and versions — never your code. `SECURITY_OFFLINE=1` disables
  that too. With `LLM_BACKEND=local`, triage runs against a model you host.
- **Nothing persists.** A scan writes no report and keeps no history; output
  goes to stdout and the process exits. If you redirect JSON or SARIF to a file,
  that file holds redacted evidence and your file paths — treat it accordingly,
  because retention is then yours to decide.
