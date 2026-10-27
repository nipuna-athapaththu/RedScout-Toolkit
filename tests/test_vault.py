import tempfile
import shutil
from redscout.vault import EvidenceVault


def test_vault_chain_valid():
    d = tempfile.mkdtemp()
    try:
        v = EvidenceVault(d)
        v.add("finding", "127.0.0.1", [{"port": 80}])
        v.add("finding", "127.0.0.1", [{"port": 443}])
        assert v.verify_chain() is True
    finally:
        shutil.rmtree(d)