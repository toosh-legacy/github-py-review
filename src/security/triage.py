"""The LLM stage: deduplicate, rank, explain, fix — never detect.

Everything upstream is deterministic. This module is the only place a model is
consulted, and its authority is deliberately bounded:

  * it may merge findings into each other
  * it may change `severity` and set `exploitability`
  * it may rewrite `explanation` and `suggested_fix`
  * it may not create a finding, change a finding's file/line/rule, or resurrect
    one the detectors did not report

That boundary is enforced in `_apply`, not requested in the prompt: replies are
matched back to detector findings by id and anything unrecognised is discarded.
A model that hallucinates simply gets ignored.

When no reviewer is configured (mock mode, offline), `deterministic_triage`
runs instead: it dedupes on location and keeps the rule-authored explanations
the detectors already carry, so the product still works with no LLM at all.
"""
from __future__ import annotations

from collections import defaultdict

from config import settings
from schemas import SecurityFinding

_VALID_SEVERITY = {"high", "medium", "low"}
_VALID_EXPLOIT = {"direct", "conditional", "theoretical"}

_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
_EXPLOIT_ORDER = {"direct": 0, "conditional": 1, "theoretical": 2, None: 3}

# Ranking a finding needs its neighbours in view, so triage runs in batches
# rather than one finding at a time. Small local models lose coherence on long
# lists well before the context window fills — 3B-class models start silently
# dropping entries somewhere around eight, so the default is deliberately below
# what a frontier model could handle. Raise it when pointing at a hosted model.
BATCH_SIZE = 8

# How much of a finding's evidence to hand the model. Secrets are already
# redacted upstream; this bounds prompt size, not exposure.
_EVIDENCE_LIMIT = 400


def _detector_rank(f: SecurityFinding) -> tuple:
    """Order findings by how much a human should care, before any LLM input."""
    return (
        _SEVERITY_ORDER.get(f.severity, 3),
        _EXPLOIT_ORDER.get(f.exploitability, 3),
        {"secret": 0, "dependency": 1, "code": 2}.get(f.category, 3),
        f.file,
        f.line_start,
    )


# --------------------------------------------------------------------------- #
# Deterministic path — also the fallback when the model is unavailable.
# --------------------------------------------------------------------------- #
def deterministic_triage(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    """Dedupe by location and sort, using the detectors' own explanations.

    Two findings collapse when they are the same category on the same line of
    the same file — that is a rule and a linter noticing one problem, not two
    problems. The higher-severity one survives and records the other's id.
    """
    groups: dict[tuple, list[SecurityFinding]] = defaultdict(list)
    for f in findings:
        if f.category == "dependency":
            # Location means nothing for a dependency; the vulnerability id and
            # the package are the identity.
            key = (f.category, f.rule_id, f.evidence)
        else:
            key = (f.category, f.file, f.line_start)
        groups[key].append(f)

    kept: list[SecurityFinding] = []
    for group in groups.values():
        group.sort(key=_detector_rank)
        winner = group[0]
        merged = [o.id for o in group[1:]]
        if merged:
            winner = winner.model_copy(
                update={"merged_from": sorted(set(winner.merged_from) | set(merged))}
            )
        kept.append(winner)

    kept.sort(key=_detector_rank)
    return kept


# --------------------------------------------------------------------------- #
# LLM path
# --------------------------------------------------------------------------- #
def _render(f: SecurityFinding, context: str) -> str:
    """One finding, as compact text for the prompt."""
    lines = [
        f"- id: {f.id}",
        f"  category: {f.category}   detector: {f.detector}   rule: {f.rule_id}",
        f"  title: {f.title}",
        f"  location: {f.file}:{f.line_start}",
        f"  scanner_severity: {f.detector_severity}",
    ]
    if f.evidence:
        lines.append(f"  evidence: {f.evidence[:_EVIDENCE_LIMIT]}")
    if f.explanation:
        lines.append(f"  scanner_note: {f.explanation[:_EVIDENCE_LIMIT]}")
    if context:
        indented = "\n".join("      " + ln for ln in context.splitlines())
        lines.append("  code:\n" + indented)
    return "\n".join(lines)


def _batches(findings: list[SecurityFinding]) -> list[list[SecurityFinding]]:
    """Group findings into batches, keeping same-file findings together so the
    model can see that two of them are the same problem."""
    by_file: dict[str, list[SecurityFinding]] = defaultdict(list)
    for f in findings:
        by_file[f.file].append(f)

    batches: list[list[SecurityFinding]] = []
    current: list[SecurityFinding] = []
    for group in by_file.values():
        for f in group:
            current.append(f)
            if len(current) >= BATCH_SIZE:
                batches.append(current)
                current = []
    if current:
        batches.append(current)
    return batches


def _apply(
    batch: list[SecurityFinding], data: dict | None
) -> list[SecurityFinding] | None:
    """Merge a model reply into `batch`. Returns None if the reply is unusable.

    This is the trust boundary, and it is enforced per finding rather than per
    batch. Only ids present in `batch` are honoured; only the four triage fields
    are writable; file, line, rule and detector are immutable.

    An id the model simply did not mention is **kept, untriaged** — not dropped.
    That distinction is what makes the whole thing work on small models: a 3B
    model handed a dozen findings will routinely return eleven, and an
    all-or-nothing contract would throw away good triage for the other ten every
    single time. Losing a finding is unacceptable; losing an *annotation* on one
    finding is not, and `triaged=False` says which happened.

    A finding is only ever removed by being named in another finding's
    `duplicate_ids`, which is the intended merge.
    """
    if not data or not isinstance(data.get("findings"), list):
        return None

    by_id = {f.id: f for f in batch}
    updates: dict[str, dict] = {}
    merged_into: dict[str, list[str]] = {}
    dropped: set[str] = set()

    for item in data["findings"]:
        if not isinstance(item, dict):
            continue
        fid = item.get("id")
        if not isinstance(fid, str) or fid not in by_id or fid in updates:
            continue  # unknown or repeated id: the model made it up
        if fid in dropped:
            # Already merged into an earlier finding. Ignoring its own duplicate
            # claims is what stops a reciprocal "A dupes B, B dupes A" pair from
            # deleting both.
            continue

        dupes = [
            d
            for d in (item.get("duplicate_ids") or [])
            if isinstance(d, str) and d in by_id and d != fid and d not in updates
        ]
        updates[fid] = item
        if dupes:
            merged_into[fid] = dupes
            dropped.update(dupes)

    if not updates:
        return None  # nothing usable came back at all

    out: list[SecurityFinding] = []
    for fid, base in by_id.items():
        if fid in dropped:
            continue
        item = updates.get(fid)
        if item is None:
            # The model skipped it. Keep the detector's finding as-is.
            out.append(base)
            continue

        severity = item.get("severity")
        if not isinstance(severity, str) or severity.lower() not in _VALID_SEVERITY:
            severity = base.detector_severity
        else:
            severity = severity.lower()

        exploitability = item.get("exploitability")
        if not isinstance(exploitability, str):
            exploitability = None
        elif exploitability.lower() not in _VALID_EXPLOIT:
            exploitability = None
        else:
            exploitability = exploitability.lower()

        explanation = str(item.get("explanation") or "").strip()
        suggested_fix = str(item.get("suggested_fix") or "").strip()

        out.append(
            base.model_copy(
                update={
                    "severity": severity,
                    "exploitability": exploitability,
                    # Keep the rule-authored text when the model gives nothing.
                    "explanation": explanation or base.explanation,
                    "suggested_fix": suggested_fix or base.suggested_fix,
                    "merged_from": sorted(
                        set(base.merged_from) | set(merged_into.get(fid, []))
                    ),
                    "triaged": True,
                }
            )
        )
    return out


def triage(
    findings: list[SecurityFinding],
    contexts: dict[str, str] | None = None,
    *,
    repo: str | None = None,
) -> tuple[list[SecurityFinding], int]:
    """Deduplicate, rank, explain and fix. Returns (findings, tokens_used).

    `contexts` maps finding id → a few lines of surrounding source, so the model
    can judge exploitability against the real code rather than the rule name.
    """
    if not findings:
        return [], 0

    # Collapse the obvious duplicates first: it is cheaper and more reliable
    # than paying the model to notice that two rules hit the same line.
    findings = deterministic_triage(findings)

    if not settings.security_triage:
        return findings, 0

    from llm_model.base import ChatLLM, get_llm
    from llm_model.prompts import TRIAGE_SYSTEM_PROMPT, TRIAGE_USER_PROMPT

    llm = get_llm()
    if not isinstance(llm, ChatLLM):
        # No model configured. The deterministic result is the product.
        return findings, 0

    contexts = contexts or {}
    triaged: list[SecurityFinding] = []
    tokens = 0

    for batch in _batches(findings):
        rendered = "\n".join(_render(f, contexts.get(f.id, "")) for f in batch)
        user = TRIAGE_USER_PROMPT.format(
            repo=repo or "(unknown)", count=len(batch), findings=rendered
        )
        try:
            data, used = llm.chat_json(TRIAGE_SYSTEM_PROMPT, user)
            tokens += used
        except Exception:  # noqa: BLE001
            # Triage is an enhancement, not the product. A dead model must not
            # cost the user their findings.
            triaged.extend(batch)
            continue

        applied = _apply(batch, data)
        triaged.extend(applied if applied is not None else batch)

    triaged.sort(key=_detector_rank)
    return triaged, tokens
