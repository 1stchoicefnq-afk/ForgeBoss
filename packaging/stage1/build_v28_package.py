from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

PACKAGE_DIR_NAME = "ForgeBoss-Stage1-Turn-On-Pack"
ZIP_NAME = "ForgeBoss-Stage1-Turn-On-Pack-v28.2-R8.2-EXACT-CHECKOUT-CANDIDATE.zip"


def sha256(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda:fh.read(1024*1024),b""):h.update(chunk)
    return h.hexdigest()


def load_verifier(path: Path):
    spec=importlib.util.spec_from_file_location("forgeboss_v28_package_verifier",path)
    if spec is None or spec.loader is None:raise RuntimeError("verifier import failed")
    module=importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode=True
    spec.loader.exec_module(module)
    return module


def package_manifest(root: Path, *, engine_sha: str, engine_ref: str, builder_image: str) -> dict:
    files={}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts:
            continue
        if path.is_dir():continue
        rel=path.relative_to(root).as_posix()
        if rel=="PACKAGE-MANIFEST.json":continue
        files[rel]={"sha256":sha256(path),"sizeBytes":path.stat().st_size}
    return {
        "schema":2,
        "packageVersion":"v28.2-r8.2",
        "packageAuthority":"OWNER_DELIVERED_UNSIGNED_PACKAGE",
        "engineSha":engine_sha,
        "engineRef":engine_ref,
        "builderImage":builder_image,
        "staticVerificationClaims":False,
        "packageProcesswideStdlibMonkeypatches":0,
        "files":files,
    }


def write_manifest(root: Path, manifest: dict) -> None:
    (root/"PACKAGE-MANIFEST.json").write_text(
        json.dumps(manifest,sort_keys=True,indent=2,ensure_ascii=False)+"\n",encoding="utf-8",newline="\n"
    )


def expect_verifier_failure(verifier, root: Path, label: str) -> str:
    try:
        verifier.verify_package(root)
    except Exception as ex:
        return f"{label}: {type(ex).__name__}: {ex}"
    raise AssertionError(label+" unexpectedly passed")


def update_manifest_file(root:Path,rel:str)->None:
    mp=root/"PACKAGE-MANIFEST.json"
    m=json.loads(mp.read_text(encoding="utf-8"))
    p=root/rel
    m["files"][rel]={"sha256":sha256(p),"sizeBytes":p.stat().st_size}
    write_manifest(root,m)


def hostile_checks(verifier, root:Path)->list[str]:
    evidence=[]
    baseline=verifier.verify_package(root)
    evidence.append(f"baseline files={baseline['filesVerified']}")

    manifest=json.loads((root/"PACKAGE-MANIFEST.json").read_text(encoding="utf-8"))
    for rel in sorted(manifest["files"]):
        p=root/rel
        original=p.read_bytes()
        p.write_bytes(original+b"\n# FORGEBOSS_TAMPER_PROBE\n")
        evidence.append(expect_verifier_failure(verifier,root,"tamper:"+rel))
        p.write_bytes(original)
    verifier.verify_package(root)

    extra=root/"UNEXPECTED-FILE.txt"
    extra.write_text("unexpected\n",encoding="utf-8")
    evidence.append(expect_verifier_failure(verifier,root,"extra-file"))
    extra.unlink()

    victim=next(iter(sorted(manifest["files"])))
    vp=root/victim;raw=vp.read_bytes();vp.unlink()
    evidence.append(expect_verifier_failure(verifier,root,"missing-file:"+victim))
    vp.parent.mkdir(parents=True,exist_ok=True);vp.write_bytes(raw)

    static=root/"PACKAGE-VERIFICATION.json"
    static.write_text('{"ok":true}\n',encoding="utf-8")
    evidence.append(expect_verifier_failure(verifier,root,"static-verification"))
    static.unlink()

    py1="Authority/authority_diagnose.py"
    p1=root/py1;old1=p1.read_bytes();old_manifest=(root/"PACKAGE-MANIFEST.json").read_bytes()
    p1.write_bytes(old1+b"\nimport os as banana\nbanana.mkdir=lambda *a,**k: None\n")
    update_manifest_file(root,py1)
    evidence.append(expect_verifier_failure(verifier,root,"renamed-os-mkdir-monkeypatch"))
    p1.write_bytes(old1);(root/"PACKAGE-MANIFEST.json").write_bytes(old_manifest)

    py2="Authority/authority_user_host.py"
    p2=root/py2;old2=p2.read_bytes();old_manifest=(root/"PACKAGE-MANIFEST.json").read_bytes()
    p2.write_bytes(old2+b"\nimport subprocess as forge\nsetattr(forge,'Popen',object)\n")
    update_manifest_file(root,py2)
    evidence.append(expect_verifier_failure(verifier,root,"renamed-popen-setattr-monkeypatch"))
    p2.write_bytes(old2);(root/"PACKAGE-MANIFEST.json").write_bytes(old_manifest)

    p1=root/py1;old1=p1.read_bytes();old_manifest=(root/"PACKAGE-MANIFEST.json").read_bytes()
    p1.write_bytes(old1+b"\ndef _stage1_finish_line_one_plan():\n    return 1\n")
    update_manifest_file(root,py1)
    harmless=verifier.verify_package(root)
    evidence.append(f"harmless-symbol-rename: PASS files={harmless['filesVerified']}")
    p1.write_bytes(old1);(root/"PACKAGE-MANIFEST.json").write_bytes(old_manifest)

    final=verifier.verify_package(root)
    evidence.append(f"restored-baseline files={final['filesVerified']}")
    return evidence


def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--template",required=True)
    ap.add_argument("--verifier",required=True)
    ap.add_argument("--lock",required=True)
    ap.add_argument("--image-digest",required=True)
    ap.add_argument("--engine-sha",required=True)
    ap.add_argument("--engine-ref",required=True)
    ap.add_argument("--out-dir",required=True)
    ns=ap.parse_args()

    engine_sha=ns.engine_sha.lower()
    if not re.fullmatch(r"[0-9a-f]{40}",engine_sha):raise SystemExit("invalid exact engine SHA")
    digest=Path(ns.image_digest).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"python@sha256:[0-9a-f]{64}",digest):raise SystemExit("invalid builder image digest")
    builder_image="python:3.13-bookworm@"+digest.split("@",1)[1]

    out=Path(ns.out_dir).resolve()
    if out.exists():shutil.rmtree(out)
    out.mkdir(parents=True)
    root=out/PACKAGE_DIR_NAME
    shutil.copytree(Path(ns.template),root)
    shutil.copy2(ns.verifier,root/"Tools"/"verify_package.py")
    shutil.copy2(ns.lock,root/"requirements.lock")

    install=root/"Install-Stage1.ps1"
    text=install.read_text(encoding="utf-8")
    replacements={
        "@@ENGINE_SHA@@":engine_sha,
        "@@ENGINE_REF@@":ns.engine_ref,
        "@@IMAGE_DIGEST@@":builder_image,
    }
    for old,new in replacements.items():
        if text.count(old)!=1:raise RuntimeError(f"placeholder mismatch: {old}")
        text=text.replace(old,new)
    install.write_text(text,encoding="utf-8",newline="\n")

    for cache in list(root.rglob("__pycache__")):
        shutil.rmtree(cache,ignore_errors=True)
    if (root/"PACKAGE-VERIFICATION.json").exists():
        raise RuntimeError("static PACKAGE-VERIFICATION.json is forbidden")

    manifest=package_manifest(root,engine_sha=engine_sha,engine_ref=ns.engine_ref,builder_image=builder_image)
    write_manifest(root,manifest)

    verifier=load_verifier(Path(ns.verifier))
    baseline=verifier.verify_package(root)
    mutation_evidence=hostile_checks(verifier,root)
    final=verifier.verify_package(root)

    zip_path=out/ZIP_NAME
    with zipfile.ZipFile(zip_path,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=9) as zf:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                zf.write(p,Path(PACKAGE_DIR_NAME)/p.relative_to(root))

    with tempfile.TemporaryDirectory() as td:
        with zipfile.ZipFile(zip_path) as zf:
            bad=zf.testzip()
            if bad:raise RuntimeError("ZIP CRC failed: "+bad)
            zf.extractall(td)
        extracted=Path(td)/PACKAGE_DIR_NAME
        extracted_result=verifier.verify_package(extracted)

    report={
        "ok":True,
        "engineSha":engine_sha,
        "engineRef":ns.engine_ref,
        "builderImage":builder_image,
        "zip":str(zip_path),
        "zipSha256":sha256(zip_path),
        "zipBytes":zip_path.stat().st_size,
        "manifestSha256":sha256(root/"PACKAGE-MANIFEST.json"),
        "filesVerified":final["filesVerified"],
        "pythonFilesBehaviorScanned":final["pythonFilesBehaviorScanned"],
        "zipExtractVerified":extracted_result["ok"],
        "mutations":mutation_evidence,
    }
    (out/"V28-PACKAGE-BUILD-REPORT.json").write_text(
        json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8",newline="\n"
    )
    print(json.dumps(report,sort_keys=True))
    return 0

if __name__=="__main__":
    raise SystemExit(main())
