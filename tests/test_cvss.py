from redscout.cvss import score, severity


def test_critical_score():
    s = score("N", "L", "N", "N", "U", "H", "H", "H")
    assert s >= 9.0
    assert severity(s) == "Critical"


def test_low_score():
    s = score("P", "H", "H", "R", "U", "L", "L", "L")
    assert s < 4.0