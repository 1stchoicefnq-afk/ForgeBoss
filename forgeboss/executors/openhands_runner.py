from __future__ import annotations
import os,sys

def main() -> int:
    if len(sys.argv)<4:
        print("usage: openhands_runner.py PACKET.json WORKSPACE BUDGET_USD",file=sys.stderr);return 2
    if os.environ.get("FORGEBOSS_ALLOW_PAID_EXECUTOR")!="YES":
        print("FORGEBOSS SAFE STOP: paid executor gate is not enabled.");return 3
    print("FORGEBOSS SAFE STOP: OpenHands paid execution is quarantined until an independently proven in-flight dollar cap is implemented.",file=sys.stderr)
    return 12

if __name__=="__main__":raise SystemExit(main())
