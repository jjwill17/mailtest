from __future__ import annotations

from typing import Any, Dict, List


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    return "F"


def aggregate_deliverability(
    *,
    checks: List[Dict[str, Any]],
    facts: Dict[str, Any],
) -> Dict[str, Any]:
    score = 100
    categories: Dict[str, Dict[str, Any]] = {}
    reasons: List[Dict[str, Any]] = []

    for check in checks:
        impact = int(check.get("impact") or 0)
        category = check.get("category") or "other"
        score += impact

        bucket = categories.setdefault(
            category,
            {"score": 100, "impact": 0, "totals": {"pass": 0, "warn": 0, "fail": 0, "info": 0}},
        )
        bucket["score"] += impact
        bucket["impact"] += impact

        status = check.get("status") or "info"
        if status not in bucket["totals"]:
            status = "info"
        bucket["totals"][status] += 1

        severity = check.get("severity")
        if severity in ("warn", "fail"):
            reasons.append(
                {
                    "code": check.get("id"),
                    "severity": severity,
                    "delta": impact,
                    "message": check.get("message"),
                    "data": check.get("evidence") or {},
                }
            )

    for bucket in categories.values():
        bucket["score"] = max(0, min(100, int(bucket["score"])))

    final_score = max(0, min(100, int(score)))
    warnings = [r["message"] for r in reasons]

    return {
        "score": final_score,
        "grade": _grade(final_score),
        "warnings": warnings,
        "reasons": reasons,
        "facts": facts,
        "checks": checks,
        "categories": categories,
    }
