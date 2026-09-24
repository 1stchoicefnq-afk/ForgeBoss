from __future__ import annotations
import argparse, json, sys
from pathlib import Path

def load(path):
    v=json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(v,dict):raise RuntimeError("invalid json")
    return v

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--installed",required=True);ns=ap.parse_args()
    try:
        state=load(ns.installed);engine=Path(state["engineRoot"]).resolve(strict=True);sys.path.insert(0,str(engine))
        from forgeboss.protected_authority.client import ProtectedAuthorityClient
        from forgeboss.protected_authority.protocol import AuthorityError
        root=Path(state["protectedRoot"]).resolve(strict=True);cfg=load(root/"authority-config.json")
        if cfg.get("authorityApi")!="self_build_runtime_receipts_v1":
            raise RuntimeError("AUTHORITY_API_CONFIG_MISMATCH")
        client_cfg=load(Path(state["clientRoot"])/"client-config.json")
        client=ProtectedAuthorityClient.from_files(
            peer_id=client_cfg["peerId"],repository=client_cfg["repository"],
            control_revision=int(client_cfg["controlRevision"]),
            peer_private_key_file=client_cfg["peerKeyFile"],
            receipt_public_key_file=client_cfg["receiptPublicKeyFile"],pipe_name=client_cfg["pipeName"],timeout=3.0)
        response=client.self_build_current_known_good();result=response.get("result") or {}
        receipt=response.get("receipt") or {}
        if receipt.get("operation")!="self_build_current_known_good":
            raise RuntimeError("STAGE1_RECEIPT_OPERATION_MISMATCH")
        print(json.dumps({"ok":True,"authorityApi":cfg.get("authorityApi"),"receiptVerified":True,"receiptOperation":receipt.get("operation"),
              "trustGrade":result.get("trustGrade"),"revision":result.get("revision"),
              "phase":result.get("phase"),"generation":result.get("generation"),
              "manifestSha256":result.get("manifest_sha256"),"identitySha256":result.get("identity_sha256"),
              "treeSha256":result.get("tree_sha256")},sort_keys=True))
        return 0
    except Exception as ex:
        print(json.dumps({"ok":False,"error":type(ex).__name__,"code":getattr(ex,"code",None),"detail":str(ex)},sort_keys=True))
        return 13
if __name__=="__main__":raise SystemExit(main())
