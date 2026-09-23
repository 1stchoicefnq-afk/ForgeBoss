from __future__ import annotations

import json
import tempfile
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from backend.project_memory import ProjectMemoryStore, redact_secrets
from backend.project_bootstrap import create_project_scaffold, BIBLE_FILES
from backend.vault_windows import SecretLease, VaultUnavailable, WindowsVault


def test_memory_and_bible():
    with tempfile.TemporaryDirectory() as td:
        store=ProjectMemoryStore(Path(td)/"memory.db")
        p=store.create_project("Demo")
        c=store.create_conversation(p)
        m=store.add_message(p,c,"user","use sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456 for this")
        row=store.search_messages(p,"REDACTED")[0]
        assert row["redacted"]==1
        assert "sk-" not in row["content"]
        mem=store.propose_memory(p,"decision","Customer-facing app must be simple",m,0.9)
        store.validate_memory(mem,True)
        e=store.propose_bible_entry(p,"REQUIREMENTS","Must be simple for non-technical users",m)
        try:
            store.activate_bible_entry(e,owner_approved=False)
            raise AssertionError("activation should have refused")
        except PermissionError:
            pass
        store.activate_bible_entry(e,owner_approved=True)
        b=store.context_bundle(p)
        assert b.bible[0]["bible_key"]=="REQUIREMENTS"
        assert b.validated_memory[0]["category"]=="decision"
        snap=store.export_safe_snapshot(p)
        encoded=json.dumps(snap)
        assert "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in encoded
        assert "vault" not in snap and "secret" not in snap
        store.close()


def test_bootstrap():
    with tempfile.TemporaryDirectory() as td:
        p=create_project_scaffold(td,"My App","Build a quoting app",{"Audience":"Trade businesses"})
        assert (p/".forgeboss"/"BIBLE-MANIFEST.json").exists()
        manifest=json.loads((p/".forgeboss"/"BIBLE-MANIFEST.json").read_text())
        assert set(manifest["files"])==set(BIBLE_FILES)
        try:
            create_project_scaffold(td,"My App","duplicate",{})
            raise AssertionError("duplicate project should refuse overwrite")
        except FileExistsError:
            pass
        try:
            create_project_scaffold(td,"Secret App","use sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",{})
            raise AssertionError("secret-bearing intake should refuse")
        except ValueError:
            pass


def test_vault_boundary():
    vault_source=(ROOT/"backend"/"vault_windows.py").read_text(encoding="utf-8")
    configure_body=vault_source.split("def _configure_dpapi():",1)[1].split("def _blob",1)[0]
    assert "_configure_dpapi()" not in configure_body
    assert "ctypes.windll.crypt32" in configure_body and "ctypes.windll.kernel32" in configure_body
    assert "crypt32, kernel32 = _configure_dpapi()" in vault_source.split("def _dpapi_unprotect",1)[1]
    lease=SecretLease("sec_x","OpenAI","p1","r1",10**12,"supersecret")
    assert "supersecret" not in repr(lease)
    assert lease.reveal("p1","r1")=="supersecret"
    try:
        import pickle
        pickle.dumps(lease)
        raise AssertionError("secret lease serialization should fail")
    except TypeError:
        pass
    try:
        lease.reveal("other","r1")
        raise AssertionError("scope mismatch should fail")
    except PermissionError:
        pass
    import os
    if os.name != "nt":
        try:
            WindowsVault()
            raise AssertionError("non-Windows vault must refuse insecure fallback")
        except VaultUnavailable:
            pass


if __name__=="__main__":
    tests=[test_memory_and_bible,test_bootstrap,test_vault_boundary]
    for t in tests:
        t(); print("[PASS]",t.__name__)
    print("POST-STAGE1 BACKEND SELFTEST PASS=3 FAIL=0")
