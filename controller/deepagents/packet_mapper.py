from siteboss_policy import ImmutablePacket
def from_siteboss_packet(p):
 return ImmutablePacket(p["packet_id"],p.get("expected_head_revision") or p.get("expected_head") or p["candidate_parent_sha"],p.get("role","builder"),tuple(p.get("context_files") or p.get("read_scope") or ()),tuple(p.get("allowed_files") or p.get("write_scope") or ()),tuple(p.get("required_tests") or ()),tuple(p.get("review_exclusions") or ()),int(p.get("max_commands",12)),int(p.get("max_file_modifications",8)),min(int(p.get("max_subagents",1)),1),int(p.get("max_model_calls",4)))
