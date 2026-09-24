from __future__ import annotations
import argparse
from pathlib import Path

def strip_requirement(text:str,name:str)->str:
    target=name.lower().replace("_","-")
    lines=text.splitlines(keepends=True)
    out=[];i=0;removed=False
    while i<len(lines):
        line=lines[i]
        head=line.strip().split(" ",1)[0].split("==",1)[0].lower().replace("_","-")
        if line and not line[0].isspace() and not line.lstrip().startswith("#") and head==target:
            removed=True;i+=1
            while i<len(lines):
                nxt=lines[i]
                if nxt.startswith((" ","\t")) or not nxt.strip() or nxt.lstrip().startswith("#"):
                    i+=1;continue
                break
            continue
        out.append(line);i+=1
    if not removed:raise RuntimeError("VENDORED_REQUIREMENT_NOT_FOUND:"+name)
    result="".join(out)
    for line in result.splitlines():
        if line.lower().replace("_","-").startswith(target+"=="):
            raise RuntimeError("VENDORED_REQUIREMENT_STILL_PRESENT:"+name)
    return result

def main(argv=None):
    ap=argparse.ArgumentParser();ap.add_argument("lock");ap.add_argument("name");ns=ap.parse_args(argv)
    p=Path(ns.lock);text=p.read_text(encoding="utf-8")
    p.write_text(strip_requirement(text,ns.name),encoding="utf-8",newline="\n")
    return 0
if __name__=="__main__":raise SystemExit(main())
