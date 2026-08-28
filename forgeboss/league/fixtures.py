"""Controlled benchmark fixtures for the ForgeBoss category league.

Integrity rules enforced here:
 * ``test.js`` is the acceptance oracle and is NOT part of ``allowed_files``.
   A candidate that rewrites the test can no longer manufacture a pass.
 * A pristine copy plus a digest of ``test.js`` is kept OUTSIDE the workspace so
   the runner can detect tampering and restore the real test before scoring.
 * Fixture setup failures raise instead of leaving a half-built workspace that
   would be silently misattributed to the candidate as a failed run.
"""
import hashlib,json,shutil,subprocess
from pathlib import Path

class FixtureError(RuntimeError):pass

CASES={"database":("retry.js","exports.retryable=c=>['40001'].includes(c)\n","const a=require('./retry');if(!a.retryable('40001')||!a.retryable('40P01')||a.retryable('23505'))process.exit(1)\n"),"backend":("api.js","exports.create=x=>({status:201,body:x})\n","const a=require('./api');if(a.create(null).status!==400||a.create({name:'x'}).status!==201)process.exit(1)\n"),"auth":("auth.js","exports.allowed=m=>true\n","const a=require('./auth');if(a.allowed(null)!==false||a.allowed({active:true})!==true)process.exit(1)\n"),"frontend":("ui.js","exports.toggle=x=>x\n","const u=require('./ui');if(u.toggle(false)!==true||u.toggle(true)!==false)process.exit(1)\n"),"small_bug":("util.js","exports.last=a=>a[a.length]\n","const u=require('./util');if(u.last([1,2,3])!==3)process.exit(1)\n"),"ci":("check.js","process.exit(1)\n","const c=require('./check')\n"),"tests":("calc.js","exports.clamp=(n,min,max)=>Math.min(max,n)\n","const c=require('./calc');if(c.clamp(-2,0,10)!==0||c.clamp(20,0,10)!==10)process.exit(1)\n")}
REFACTOR_ALLOWED=["a.js","b.js","normalize.js"]
# The refactor benchmark used to ship GREEN: a.js/b.js already worked and the
# test only re-checked them, so any cosmetic in-scope edit scored a pass and
# could win the category. The oracle now demands the actual deduplication into
# normalize.js, which makes the fixture start red like every other category.
REFACTOR_SRC="exports.norm=s=>String(s).trim().toLowerCase()\n"
REFACTOR_TEST=("const n=require('./normalize'),a=require('./a'),b=require('./b');\n"
 "if(typeof n.norm!=='function')process.exit(1);\n"
 "if(n.norm(' X ')!=='x'||n.norm('\\tY\\n')!=='y')process.exit(1);\n"
 "if(a.norm(' X ')!=='x'||b.norm(' Y ')!=='y')process.exit(1);\n"
 "if(a.norm!==n.norm||b.norm!==n.norm)process.exit(1);\n")
TEST_FILE="test.js"
CATEGORIES=sorted(set(CASES)|{"refactor"})

def w(p,s):p.write_text(s,encoding="utf-8")

def digest(p):
 """sha256 of the bytes actually on disk (newline translation independent)."""
 return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def _git(root,*args,check=True):
 q=subprocess.run(["git",*args],cwd=str(root),capture_output=True,text=True)
 if check and q.returncode!=0:raise FixtureError(f"git {' '.join(args)} failed rc={q.returncode}: {(q.stderr or '').strip()[:200]}")
 return q

def pristine_dir(root):
 """Sibling of the workspace: reachable by the runner, outside the candidate's tree."""
 root=Path(root);return root.parent/(root.name+".pristine")

def make(root,cat):
 """Build a benchmark workspace and return its integrity descriptor.

 Returns a dict with ``packet``, ``allowed_files`` (set), ``base_commit``,
 ``test_sha256`` and ``pristine_test``.
 """
 if cat not in CATEGORIES:raise FixtureError(f"unknown benchmark category: {cat!r}")
 root=Path(root);pdir=pristine_dir(root)
 for d in (root,pdir):
  shutil.rmtree(d,ignore_errors=True)
  if d.exists():raise FixtureError(f"could not clear fixture directory: {d}")
 root.mkdir(parents=True);pdir.mkdir(parents=True)
 if cat=="refactor":
  w(root/"a.js",REFACTOR_SRC);w(root/"b.js",REFACTOR_SRC)
  test=REFACTOR_TEST;allowed=list(REFACTOR_ALLOWED)
 else:
  fn,code,test=CASES[cat];w(root/fn,code);allowed=[fn]
 w(root/TEST_FILE,test)
 # Pristine oracle copy lives outside the workspace so the candidate cannot reach it.
 shutil.copy2(root/TEST_FILE,pdir/TEST_FILE);test_sha=digest(pdir/TEST_FILE)
 packet={"objective":f"Fix this controlled {cat} benchmark so `node {TEST_FILE}` passes. Make the smallest correct change.","allowed_files":allowed,"context_files":allowed+[TEST_FILE],"acceptance_criteria":[f"node {TEST_FILE} exits 0"],"constraints":[f"{TEST_FILE} is the immutable acceptance oracle: read it, never modify it.","Editing any file outside allowed_files voids the run."]}
 w(root/"packet.json",json.dumps(packet,indent=2))
 _git(root,"init","-q");_git(root,"config","user.email","forgeboss@local");_git(root,"config","user.name","ForgeBoss")
 _git(root,"add","-A");_git(root,"-c","commit.gpgsign=false","commit","-q","--no-verify","-m","fixture")
 base=_git(root,"rev-parse","HEAD").stdout.strip()
 if not base:raise FixtureError("fixture base commit could not be resolved")
 return {"packet":packet,"allowed_files":set(allowed),"base_commit":base,"test_sha256":test_sha,"pristine_test":pdir/TEST_FILE}
