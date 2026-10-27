"""
CVSS v3.1 base score calculator (subset - AV/AC/PR/UI/S/C/I/A).
"""
import math

METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def score(av: str, ac: str, pr: str, ui: str, scope: str,
          conf: str, integ: str, avail: str) -> float:
    scope_changed = scope == "C"
    pr_table = METRICS["PR_C"] if scope_changed else METRICS["PR_U"]

    iss = 1 - (
        (1 - METRICS["CIA"][conf]) *
        (1 - METRICS["CIA"][integ]) *
        (1 - METRICS["CIA"][avail])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    expl = (8.22 * METRICS["AV"][av] * METRICS["AC"][ac] *
            pr_table[pr] * METRICS["UI"][ui])

    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + expl), 10.0)
    return math.ceil(raw * 10) / 10


def severity(s: float) -> str:
    if s == 0: return "None"
    if s < 4.0: return "Low"
    if s < 7.0: return "Medium"
    if s < 9.0: return "High"
    return "Critical"
