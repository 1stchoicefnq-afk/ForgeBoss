from __future__ import annotations
import argparse,json,sys
from .client import Client

def main():
    ap=argparse.ArgumentParser(prog="forgebossctl")
    sub=ap.add_subparsers(dest="cmd",required=True)
    sub.add_parser("health");sub.add_parser("state")
    g=sub.add_parser("task-get");g.add_argument("task_id")
    ns=ap.parse_args()
    c=Client()
    try:
        if ns.cmd=="health":out=c.call("health")
        elif ns.cmd=="state":out=c.call("state.snapshot")
        else:out=c.call("task.get",{"taskId":ns.task_id})
        print(json.dumps(out,indent=2))
    finally:c.close()
if __name__=="__main__":main()
