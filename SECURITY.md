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

This is a scanner, so most of its interesting failure modes are about what it
does with *your* data:

- **A credential reaching a place it should not.** Findings are redacted before
  they are stored, rendered, or sent to a model. A path that leaks a raw secret
  into the database, the browser, the logs, or an LLM prompt is a vulnerability.
- **The scan payload escaping its sandbox.** Submitted files are written to a
  temporary directory so bandit and eslint can run over them. A path that
  escapes that directory is a vulnerability.
- **The server reaching a repository the caller did not send.** The API never
  fetches; anything that makes it fetch is a vulnerability.
- **The model gaining authority it should not have.** Triage may only merge,
  re-rank, and annotate findings. Anything that lets a model reply create a
  finding, change a finding's file/line/rule, or delete one without accounting
  for it as a duplicate is a vulnerability.
- Anything on the API's authenticated or network-facing surface: injection,
  SSRF, or resource exhaustion that the scan caps do not bound.

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

- **Secrets are redacted before storage.** Detectors see raw content; a
  `redact_findings` stage runs before anything is persisted or prompted, so what
  is stored is `ghp_***…***7r8 (40 chars)`, not the token. The stage's position
  in the pipeline is asserted by a test.
- **The model never sees a credential.** Code context handed to triage is
  scrubbed with the same rules.
- **Nothing leaves your infrastructure unless you configure it to.** With no LLM
  backend the scanner is fully local except for the OSV lookup, which sends only
  package names and versions — never your code. `SECURITY_OFFLINE=1` disables
  that too. With `LLM_BACKEND=local`, triage runs against a model you host.
- **Reports persist.** Scan history is stored in your database, including
  redacted evidence and file paths. Treat that database as sensitive and apply
  your own retention policy.
