from __future__ import annotations
import json,tempfile,unittest
from pathlib import Path
from unittest import mock
import forgeboss.autonomy.repair_playbook as rp

class Result:
 def __init__(self,returncode=0,stdout='',stderr=''):self.returncode=returncode;self.stdout=stdout;self.stderr=stderr

class RepairPlaybookBindingTests(unittest.TestCase):
 def setUp(self):
  self.tmp=Path(tempfile.mkdtemp());self.old_db=rp.DB;rp.DB=self.tmp/'repair-playbook.json'
 def tearDown(self):rp.DB=self.old_db
 def write(self,name,obj):
  p=self.tmp/name;p.write_text(json.dumps(obj),encoding='utf-8');return p
 def report(self):
  return {"exact_head":"base123","local_workspace":"repo","local_commit":"accepted456","builder_specialists":[],"attempts":[{"acceptance_passed":True,"changed_paths":["src/a.js"],"runs":[]}]}
 def fake_git(self,args,cwd=None,inp=None):
  if args[:3]==['git.exe','merge-base','--is-ancestor']:return Result(0)
  if args[:3]==['git.exe','diff','--name-only']:return Result(0,'src/a.js\n')
  if args[:4]==['git.exe','diff','--no-ext-diff','--binary']:
   self.assertEqual(args[4:6],['base123','accepted456'])
   return Result(0,'ACCEPTED_COMMIT_PATCH\n')
  raise AssertionError(args)
 def test_mutated_workspace_is_not_captured_as_proven_patch(self):
  report=self.write('report.json',self.report())
  with mock.patch.object(rp,'run',side_effect=self.fake_git),mock.patch.object(rp,'blob',return_value='beforehash'):
   rp.record(report)
  db=json.loads(rp.DB.read_text());e=db['entries'][0]
  self.assertEqual(e['outcome'],'proven');self.assertEqual(e['patch'],'ACCEPTED_COMMIT_PATCH\n')
  self.assertEqual(e['accepted_commit'],'accepted456');self.assertTrue(rp.binding_valid(e))
 def test_missing_or_invalid_accepted_commit_is_not_proven(self):
  r=self.report();r['local_commit']=None;report=self.write('report.json',r)
  with mock.patch.object(rp,'blob',return_value='beforehash'):rp.record(report)
  e=json.loads(rp.DB.read_text())['entries'][0]
  self.assertEqual(e['outcome'],'unbound');self.assertIsNone(e['patch'])
 def test_changed_path_mismatch_rejects_binding(self):
  report=self.write('report.json',self.report())
  def fake(args,cwd=None,inp=None):
   if args[:3]==['git.exe','merge-base','--is-ancestor']:return Result(0)
   if args[:3]==['git.exe','diff','--name-only']:return Result(0,'src/a.js\nsrc/extra.js\n')
   raise AssertionError(args)
  with mock.patch.object(rp,'run',side_effect=fake),mock.patch.object(rp,'blob',return_value='beforehash'):rp.record(report)
  e=json.loads(rp.DB.read_text())['entries'][0];self.assertEqual(e['outcome'],'unbound')
 def test_binding_mismatch_is_not_replayable(self):
  patch='PATCH\n';ph=rp.patch_sha256(patch);entry={"outcome":"proven","failure_signature":"sig","category":"backend","changed_paths":["src/a.js"],"before_sha256":{"src/a.js":"beforehash"},"patch":patch,"patch_sha256":ph,"accepted_base_sha":"base123","accepted_commit":"accepted456","binding_sha256":"wrong","seen_count":1}
  rp.DB.write_text(json.dumps({"entries":[entry]}));funnel=self.write('funnel.json',{"target_sha":"target","failure_signature":"sig","category":"backend"})
  with mock.patch.object(rp,'blob',return_value='beforehash'):self.assertIsNone(rp.find(funnel,Path('repo')))
 def test_valid_bound_entry_remains_replayable(self):
  patch='PATCH\n';ph=rp.patch_sha256(patch);entry={"outcome":"proven","failure_signature":"sig","category":"backend","changed_paths":["src/a.js"],"before_sha256":{"src/a.js":"beforehash"},"patch":patch,"patch_sha256":ph,"accepted_base_sha":"base123","accepted_commit":"accepted456","binding_sha256":rp.binding_sha256('base123','accepted456',['src/a.js'],ph),"seen_count":1}
  rp.DB.write_text(json.dumps({"entries":[entry]}));funnel=self.write('funnel.json',{"target_sha":"target","failure_signature":"sig","category":"backend"})
  with mock.patch.object(rp,'blob',return_value='beforehash'):self.assertEqual(rp.find(funnel,Path('repo'))['accepted_commit'],'accepted456')

if __name__=='__main__':unittest.main()
