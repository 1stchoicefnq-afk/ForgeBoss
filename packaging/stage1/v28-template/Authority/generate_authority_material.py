from __future__ import annotations
import argparse, base64, hashlib, json, os, sys, time
from pathlib import Path

def atomic(path:Path, data:bytes):
    path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_name(path.name+f".tmp-{os.getpid()}")
    with tmp.open("wb") as f:
        f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)

def canonical(value)->bytes:
    return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+"\n").encode()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",required=True);ap.add_argument("--client-root",required=True)
    ap.add_argument("--engine-root",required=True);ap.add_argument("--engine-sha",required=True)
    ap.add_argument("--pipe-name",required=True)
    ns=ap.parse_args()
    root=Path(ns.root).resolve(strict=True);client=Path(ns.client_root).resolve(strict=True)
    engine=Path(ns.engine_root).resolve(strict=True);sha=ns.engine_sha.lower()
    pipe_name=str(ns.pipe_name);prefix=r"\\.\pipe\ForgeBossAuthorityStage1-v"
    if not pipe_name.startswith(prefix) or not pipe_name[len(prefix):].isdigit():raise RuntimeError("AUTHORITY_PIPE_IDENTITY_INVALID")
    sys.path.insert(0,str(engine))
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from forgeboss.control.known_good import create_build_manifest, verify_build_manifest
    from forgeboss.control.activation import ActivationManager
    sid=os.environ.get("FORGEBOSS_INSTALL_USER_SID")
    if not sid:raise RuntimeError("FORGEBOSS_INSTALL_USER_SID missing")
    peer_path=client/"controller-a.key"
    receipt_path=root/"receipt-signing.key"
    if not peer_path.exists():
        key=Ed25519PrivateKey.generate()
        raw=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        atomic(peer_path,raw)
    else:
        raw=peer_path.read_bytes();key=Ed25519PrivateKey.from_private_bytes(raw)
    peer_pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    if not receipt_path.exists():
        receipt=Ed25519PrivateKey.generate()
        receipt_raw=receipt.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        atomic(receipt_path,receipt_raw)
    else:
        receipt_raw=receipt_path.read_bytes();receipt=Ed25519PrivateKey.from_private_bytes(receipt_raw)
    receipt_pub=receipt.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    atomic(client/"receipt-public.b64",base64.b64encode(receipt_pub)+b"\n")
    github_key=root/"github-disabled.key"
    if not github_key.exists():atomic(github_key,b"")
    activation=root/"activation";activation.mkdir(exist_ok=True)
    manifest_value=create_build_manifest(engine,sha,"forgeboss/control/daemon.py")
    manifest_path=activation/"initial-build-manifest.json"
    atomic(manifest_path,canonical(manifest_value))
    identity=verify_build_manifest(manifest_path,engine,sha,hashlib.sha256(manifest_path.read_bytes()).hexdigest())
    pointer=ActivationManager(activation,identity).initialize_known_good()
    cfg={
      "schema":2,"repository":"1stchoicefnq-afk/ForgeBoss","controlRevision":1,
      "protectedRoot":str(root),"engineRoot":str(engine),"engineSha":sha,
      "pipeName":pipe_name,
      "userSid":sid,"peerId":"controller-a","peerPublicKeyB64":base64.b64encode(peer_pub).decode(),
      "receiptSigningKeyFile":str(receipt_path),"receiptPublicKeyFile":str(client/"receipt-public.b64"),
      "githubPrivateKeyFile":str(github_key),"githubEnabled":False,
      "authorityApi":"self_build_runtime_receipts_v1",
      "knownGoodManifest":str(manifest_path),"knownGoodIdentity":identity,
      "createdAt":time.time()
    }
    atomic(root/"authority-config.json",canonical(cfg))
    client_cfg={"schema":2,"peerId":"controller-a","repository":cfg["repository"],"controlRevision":1,
                "peerKeyFile":str(peer_path),"receiptPublicKeyFile":cfg["receiptPublicKeyFile"],
                "protectedRoot":str(root),"engineRoot":str(engine),"engineSha":sha,"pipeName":cfg["pipeName"]}
    atomic(client/"client-config.json",canonical(client_cfg))
    print(json.dumps({"ok":True,"engineSha":sha,"manifestSha256":identity["manifestSha256"],
                      "identitySha256":identity["identitySha256"],"treeSha256":identity["treeSha256"],
                      "generation":pointer["generation"],"legacyLaunchTrust":False},sort_keys=True))
if __name__=="__main__":main()
