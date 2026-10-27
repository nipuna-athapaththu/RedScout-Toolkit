import pytest
import tempfile
from pathlib import Path
from redscout.scope_guard import ScopeGuard, ScopeError

SCOPE = """
authorized_by: tester
valid_from: "2020-01-01T00:00:00Z"
valid_until: "2099-12-31T23:59:59Z"
targets:
  - "127.0.0.1"
  - "10.0.0.0/24"
allowed_techniques:
  - port_scan
"""


@pytest.fixture
def scope_file():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(SCOPE)
        return f.name


def test_allowed_ip(scope_file):
    g = ScopeGuard(scope_file)
    assert g.check_target("127.0.0.1") is True


def test_allowed_network(scope_file):
    g = ScopeGuard(scope_file)
    assert g.check_target("10.0.0.5") is True


def test_denied_target(scope_file):
    g = ScopeGuard(scope_file)
    with pytest.raises(ScopeError):
        g.check_target("8.8.8.8")


def test_technique_allowed(scope_file):
    g = ScopeGuard(scope_file)
    assert g.is_technique_allowed("port_scan") is True
    assert g.is_technique_allowed("exploitation") is False
    