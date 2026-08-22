from dataclasses import dataclass,field
from pathlib import Path,PurePosixPath
import os,re,subprocess
class SecurityDenial(RuntimeError):pass
class StalePacket(RuntimeError):pass
class BudgetExceeded(RuntimeError):pass
@dataclass(frozen=True)
class ImmutablePacket:
 packet_id:str;expected_head:str;role:str;read_scope:tuple[str,...];write_scope:tuple[str,...]
 required_tests:tuple[str,...]=();review_exclusions:tuple[str,...]=();max_commands:int=12;max_file_modifications:int=8;max_subagents:int=1;max_model_calls:int=4
@dataclass
class Evidence:
 files_read:list[str]=field(default_factory=list);files_changed:list[str]=field(default_factory=list);commands_run:list[dict]=field(default_factory=list);tests:list[dict]=field(default_factory=list)
def norm(p):
 if not isinstance(p,str) or not p.strip():raise SecurityDenial("empty path")
 p=p.replace("\\","/")
 if re.match(r"^[A-Za-z]:",p) or p.startswith("//"):raise SecurityDenial("absolute host path denied")
 if p.startswith("~"):raise SecurityDenial("home expansion denied")
 pp=PurePosixPath("/"+p.lstrip("/"))
 if ".." in pp.parts:raise SecurityDenial("parent traversal denied")
 return pp.as_posix().lstrip("/")
def under(rel,scopes):
 rel=norm(rel);return any(rel==norm(s) or rel.startswith(norm(s).rstrip("/")+"/") for s in scopes)
class GuardedWorkspace:
 def __init__(self,root,packet):self.root=Path(root).resolve();self.packet=packet;self.evidence=Evidence();self.command_count=0;self.modified=set()
 def real(self,rel):
  rel=norm(rel);candidate=(self.root/rel).resolve(strict=False)
  try:candidate.relative_to(self.root)
  except ValueError as e:raise SecurityDenial("workspace escape denied") from e
  cur=self.root
  for part in Path(rel).parts:
   cur=cur/part
   if cur.exists():
    try:cur.resolve().relative_to(self.root)
    except ValueError as e:raise SecurityDenial("symlink/junction escape denied") from e
  return candidate
 def read_text(self,rel):
  if not under(rel,self.packet.read_scope) and not under(rel,self.packet.write_scope):raise SecurityDenial("read outside packet scope")
  x=self.real(rel).read_text(encoding="utf-8");self.evidence.files_read.append(norm(rel));return x
 def write_text(self,rel,content):
  if not under(rel,self.packet.write_scope):raise SecurityDenial("write outside packet scope")
  n=norm(rel)
  if len(self.modified|{n})>self.packet.max_file_modifications:raise BudgetExceeded("max file modifications")
  p=self.real(rel);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(content,encoding="utf-8");self.modified.add(n);self.evidence.files_changed.append(n)
 def run_command(self,argv,test=False):
  if self.command_count>=self.packet.max_commands:raise BudgetExceeded("max command count")
  if not argv:raise SecurityDenial("empty command")
  if Path(argv[0]).name.lower() not in {"node","node.exe","npm","npm.cmd","npx","npx.cmd","python","python.exe","pytest","pytest.exe"}:raise SecurityDenial("command class denied")
  self.command_count+=1
  r=subprocess.run(argv,cwd=self.root,text=True,capture_output=True,timeout=300,shell=False,env={"PATH":os.environ.get("PATH",""),"NODE_ENV":"test","SITEBOSS_SANDBOX":"1"})
  rec={"argv":argv,"exit_code":r.returncode,"stdout":r.stdout[-20000:],"stderr":r.stderr[-20000:]};self.evidence.commands_run.append(rec)
  if test:self.evidence.tests.append(rec)
  return rec
def revalidate_resume(packet,current_head,lease_valid,controller_version_ok):
 if current_head!=packet.expected_head:raise StalePacket("STALE_GITHUB_HEAD")
 if not lease_valid:raise StalePacket("LEASE_EXPIRED")
 if not controller_version_ok:raise StalePacket("STALE_CONTROLLER_VERSION")
