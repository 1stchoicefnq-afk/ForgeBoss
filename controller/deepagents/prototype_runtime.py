import json
from typing import Literal
from pydantic import BaseModel,Field
from siteboss_policy import ImmutablePacket,GuardedWorkspace
class SiteBossResult(BaseModel):
 packet_id:str;status:Literal["COMPLETED","BLOCKED","FAILED"];specialists_used:list[str]=Field(default_factory=list);files_read:list[str]=Field(default_factory=list);files_changed:list[str]=Field(default_factory=list);commands_run:list[dict]=Field(default_factory=list);tests:list[dict]=Field(default_factory=list);findings:list[str]=Field(default_factory=list);blockers:list[str]=Field(default_factory=list);scope_respected:bool=True;write_authority_respected:bool=True;review_required:bool=True;checkpoint:str|None=None
def build_deep_agent(packet:ImmutablePacket,workspace:GuardedWorkspace,specialist_prompt:str,model:str):
 try:
  from deepagents import create_deep_agent
  from langchain_core.tools import tool
 except ImportError as e:raise RuntimeError("DEEP_AGENTS_NOT_INSTALLED") from e
 @tool
 def sb_read_file(path:str)->str:
  """Read only packet-authorised files."""
  return workspace.read_text(path)
 @tool
 def sb_write_file(path:str,content:str)->str:
  """Write only packet-authorised files."""
  workspace.write_text(path,content);return "written"
 @tool
 def sb_run_test(argv:list[str])->dict:
  """Run only SiteBoss-approved test command classes."""
  return workspace.run_command(argv,test=True)
 authority={"packet_id":packet.packet_id,"expected_head":packet.expected_head,"role":packet.role,"read_scope":packet.read_scope,"write_scope":packet.write_scope,"required_tests":packet.required_tests,"rule":"immutable; planning never grants scope; denials are final"}
 return create_deep_agent(model=model,tools=[sb_read_file,sb_write_file,sb_run_test],system_prompt="SITEBOSS AUTHORITY:\n"+json.dumps(authority)+"\nSPECIALIST:\n"+specialist_prompt,response_format=SiteBossResult,subagents=[])
