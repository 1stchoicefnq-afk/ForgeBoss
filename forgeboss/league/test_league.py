"""Regression tests for confirmed ForgeBoss league correctness defects.

Every test below pins a bug that was live in the league subsystem: unvalidated
agent-reported cost defeating the budget cap, NaN poisoning winner selection and
persisted JSON, a rewritten test.js manufacturing a false winner, committed work
scoring as "no changes", dropped result rows, crash-loses-everything, and
concurrent leagues corrupting league-last.json.
"""
from __future__ import annotations
import json,math,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
import fixtures,run_league as L

HAS_GIT=subprocess.run(["git","--version"],capture_output=True).returncode==0
HAS_NODE=subprocess.run(["node","--version"],capture_output=True).returncode==0


class CostValidationTests(unittest.TestCase):
 """Agent-reported cost is untrusted input."""
 def test_nan_cost_is_rejected(self):
  self.assertEqual(L.coerce_cost(float("nan")),(None,"non_finite"))
 def test_infinite_cost_is_rejected(self):
  self.assertEqual(L.coerce_cost(float("inf")),(None,"non_finite"))
  self.assertEqual(L.coerce_cost(float("-inf")),(None,"non_finite"))
 def test_nan_string_cost_is_rejected(self):
  for s in ("nan","NaN","inf","-Infinity"):
   self.assertEqual(L.coerce_cost(s)[0],None,s)
 def test_negative_cost_is_rejected(self):
  self.assertEqual(L.coerce_cost(-5.0),(None,"negative"))
 def test_non_numeric_cost_is_rejected(self):
  for v in ("abc",{},[],object(),True,False):
   self.assertIsNone(L.coerce_cost(v)[0],repr(v))
 def test_missing_cost_is_reported_as_missing(self):
  self.assertEqual(L.coerce_cost(None),(None,"missing"))
  self.assertEqual(L.coerce_cost("  "),(None,"missing"))
 def test_valid_costs_pass_through(self):
  self.assertEqual(L.coerce_cost(0),(0.,"ok"))
  self.assertEqual(L.coerce_cost(0.12),(0.12,"ok"))
  self.assertEqual(L.coerce_cost("0.25"),(0.25,"ok"))

 def test_unusable_cost_is_charged_the_full_allocation(self):
  """Silence must not be free: an unreported cost previously added 0.0 to
  `spent`, so a non-reporting executor could run the field unbounded."""
  self.assertEqual(L.charge_for(None,0.05),0.05)
  self.assertEqual(L.charge_for(float("nan"),0.05),0.05)
  self.assertEqual(L.charge_for(-3.0,0.05),0.05)
 def test_valid_cost_is_charged_as_reported(self):
  self.assertEqual(L.charge_for(0.02,0.05),0.02)

 def test_budget_cap_cannot_be_defeated_by_nan(self):
  """`spent += float('nan')` made every `spent >= target*.9` check false
  forever, disabling the budget reserve entirely."""
  charged=0.
  for _ in range(100):charged+=L.charge_for(L.coerce_cost(float("nan"))[0],0.05)
  self.assertTrue(math.isfinite(charged))
  self.assertGreaterEqual(charged,1.0*L.BUDGET_RESERVE)


class ResultMarkerTests(unittest.TestCase):
 def test_non_object_payload_does_not_crash(self):
  """`json.loads('[1,2]')` returned a list and `.get` blew up the league."""
  for bad in ("[1,2]","5","null",'"x"'):
   self.assertEqual(L.meta(L.RESULT_PREFIX+bad),{})
 def test_malformed_json_is_ignored(self):
  self.assertEqual(L.meta(L.RESULT_PREFIX+"{not json"),{})
 def test_last_valid_object_wins(self):
  txt="\n".join([L.RESULT_PREFIX+'{"cost_usd":1}',L.RESULT_PREFIX+'{"cost_usd":2}'])
  self.assertEqual(L.meta(txt),{"cost_usd":2})
 def test_falls_back_past_a_malformed_trailing_marker(self):
  txt="\n".join([L.RESULT_PREFIX+'{"cost_usd":1}',L.RESULT_PREFIX+"[]"])
  self.assertEqual(L.meta(txt),{"cost_usd":1})
 def test_no_marker_returns_empty(self):
  self.assertEqual(L.meta("just agent chatter\n"),{})
  self.assertEqual(L.meta(None),{})


class LeaseParsingTests(unittest.TestCase):
 def test_empty_lease_output_raises_instead_of_indexerror(self):
  with self.assertRaises(L.LeaseError):L.parse_lease("")
  with self.assertRaises(L.LeaseError):L.parse_lease("   \n\n")
 def test_non_json_lease_raises(self):
  with self.assertRaises(L.LeaseError):L.parse_lease("granted!")
 def test_non_object_lease_raises(self):
  with self.assertRaises(L.LeaseError):L.parse_lease("[1,2]")
 def test_missing_fields_raise(self):
  with self.assertRaises(L.LeaseError):L.parse_lease('{"lease":"a"}')
  with self.assertRaises(L.LeaseError):L.parse_lease('{"lease":"","token":"t"}')
  with self.assertRaises(L.LeaseError):L.parse_lease('{"lease":"a","token":5}')
 def test_valid_lease_is_read_from_the_last_line(self):
  self.assertEqual(L.parse_lease('noise\n{"lease":"a","token":"t"}\n'),("a","t"))


class WinnerSelectionTests(unittest.TestCase):
 def row(self,ex,charged,elapsed=1.0,passed=True,**kw):
  d={"executor":ex,"budget_charged_usd":charged,"elapsed_seconds":elapsed,"passed":passed,"candidate_index":0};d.update(kw);return d

 def test_no_passing_candidate_designates_nobody(self):
  self.assertIsNone(L.select_winner([self.row("a",.1,passed=False)]))
  self.assertIsNone(L.select_winner([]))
 def test_cheapest_passing_candidate_wins(self):
  w=L.select_winner([self.row("a",.10),self.row("b",.02)])
  self.assertEqual(w["executor"],"b")
 def test_only_passing_rows_are_eligible(self):
  w=L.select_winner([self.row("cheat",.00,passed=False),self.row("real",.90)])
  self.assertEqual(w["executor"],"real")
 def test_truthy_but_non_true_passed_is_not_a_win(self):
  """`x.get('passed')` accepted any truthy value; passed must be exactly True."""
  self.assertIsNone(L.select_winner([self.row("a",.01,passed="yes")]))
  self.assertIsNone(L.select_winner([self.row("a",.01,passed=1)]))
 def test_nan_cost_cannot_scramble_the_ordering(self):
  """NaN sort keys compare False against everything, so a poisoned float used
  to make ordering depend on list position and could crown a false winner."""
  rows=[self.row("poison",float("nan")),self.row("honest",.05)]
  self.assertEqual(L.select_winner(rows)["executor"],"honest")
  self.assertEqual(L.select_winner(list(reversed(rows)))["executor"],"honest")
 def test_non_numeric_cost_sorts_last_not_first(self):
  rows=[self.row("junk","free"),self.row("honest",.05)]
  self.assertEqual(L.select_winner(rows)["executor"],"honest")
 def test_ties_break_deterministically_by_name(self):
  rows=[self.row("zeta",.05,2.0),self.row("alpha",.05,2.0)]
  self.assertEqual(L.select_winner(rows)["executor"],"alpha")
  self.assertEqual(L.select_winner(list(reversed(rows)))["executor"],"alpha")
 def test_elapsed_breaks_a_cost_tie_before_name(self):
  rows=[self.row("zeta",.05,1.0),self.row("alpha",.05,9.0)]
  self.assertEqual(L.select_winner(rows)["executor"],"zeta")
 def test_ordering_is_stable_across_input_permutations(self):
  import itertools
  rows=[self.row("a",.05,3.),self.row("b",.05,1.),self.row("c",.01,9.)]
  names={L.select_winner(list(p))["executor"] for p in itertools.permutations(rows)}
  self.assertEqual(names,{"c"})
 def test_winner_ranks_on_charged_not_self_reported_cost(self):
  """Ranking on the raw report rewarded lying; the charged figure is used."""
  liar=self.row("liar",.05,reported_cost_usd=0.0)
  honest=self.row("honest",.01,reported_cost_usd=0.01)
  self.assertEqual(L.select_winner([liar,honest])["executor"],"honest")


class CandidateHygieneTests(unittest.TestCase):
 def test_duplicate_candidates_are_collapsed(self):
  uniq,dropped=L.dedupe(["mini-swe","openhands","mini-swe"])
  self.assertEqual(uniq,["mini-swe","openhands"]);self.assertEqual(dropped,["mini-swe"])
 def test_dedupe_preserves_first_occurrence_order(self):
  self.assertEqual(L.dedupe(["b","a","b","a"])[0],["b","a"])
 def test_blank_and_non_string_candidates_are_dropped(self):
  uniq,dropped=L.dedupe(["ok","",None,3,"  "])
  self.assertEqual(uniq,["ok"]);self.assertEqual(len(dropped),4)
 def test_whitespace_is_not_a_distinct_identity(self):
  self.assertEqual(L.dedupe(["mini-swe"," mini-swe "])[0],["mini-swe"])

 def test_unknown_executor_is_skipped_not_silently_run_as_opencode(self):
  """The old `if ex in (...) else opencode` dispatch ran OpenCode for any
  typo'd executor name, quietly paying a quarantined engine."""
  out=L.run_candidate("small_bug","mini-sw3",.05,{},1)
  self.assertEqual(out["status"],"skipped");self.assertIn("unknown executor",out["skipped"])
  self.assertNotIn("workspace",out)


class TargetBudgetTests(unittest.TestCase):
 def test_clamped_to_configured_range(self):
  self.assertEqual(L.parse_target(["x","0.01"]),L.MIN_TARGET)
  self.assertEqual(L.parse_target(["x","99"]),L.MAX_TARGET)
  self.assertEqual(L.parse_target(["x","1.5"]),1.5)
 def test_default_is_one_dollar(self):
  self.assertEqual(L.parse_target(["x"]),1.0)
 def test_nan_and_inf_targets_are_rejected(self):
  for bad in ("nan","inf","-inf"):
   with self.assertRaises(L.LeagueError):L.parse_target(["x",bad])
 def test_junk_target_is_rejected_with_a_clear_error(self):
  with self.assertRaisesRegex(L.LeagueError,"LEAGUE_BAD_TARGET_BUDGET"):L.parse_target(["x","free"])


class CategoryLoadingTests(unittest.TestCase):
 def load(self,doc):
  p=Path(tempfile.mkdtemp())/"c.json";p.write_text(json.dumps(doc),encoding="utf-8");return L.load_categories(p)
 def test_shipped_categories_are_valid(self):
  cats=L.load_categories(L.HERE/"categories.json")
  self.assertEqual(len(cats),8)
  for cat,cands in cats.items():
   self.assertIn(cat,fixtures.CATEGORIES,cat)
   self.assertEqual(L.dedupe(cands)[1],[],f"{cat} has duplicate candidates")
   for ex in cands:self.assertIn(ex,L.RUNNERS,ex)
 def test_category_order_is_sorted_not_file_order(self):
  self.assertEqual(list(self.load({"categories":{"z":["a"],"a":["b"]}})),["a","z"])
 def test_malformed_documents_are_rejected(self):
  for doc in ([1,2],{},{"categories":[]},{"categories":{}},{"categories":{"a":"mini-swe"}}):
   with self.assertRaises(L.LeagueError,msg=repr(doc)):self.load(doc)
 def test_unreadable_file_is_rejected(self):
  with self.assertRaises(L.LeagueError):L.load_categories(Path(tempfile.mkdtemp())/"missing.json")


class StrictJsonTests(unittest.TestCase):
 def test_nan_is_never_emitted_into_persisted_json(self):
  """json.dumps emits bare `NaN`/`Infinity` by default, which is not valid
  JSON: league-last.json became unparseable by every strict reader."""
  text=L.dumps({"reported_cost_usd":float("nan"),"e":float("inf")})
  self.assertNotIn("NaN",text);self.assertNotIn("Infinity",text)
  self.assertEqual(json.loads(text),{"reported_cost_usd":None,"e":None})
 def test_nested_and_unserializable_values_are_coerced(self):
  text=L.dumps({"a":[float("nan"),{"b":float("-inf")}],"p":Path("/tmp/x"),"s":{1,2}})
  doc=json.loads(text)
  self.assertEqual(doc["a"],[None,{"b":None}]);self.assertIsInstance(doc["p"],str);self.assertEqual(len(doc["s"]),2)
 def test_ordinary_values_survive_untouched(self):
  self.assertEqual(json.loads(L.dumps({"a":1,"b":None,"c":True,"d":"x",'e':.5})),{"a":1,"b":None,"c":True,"d":"x","e":.5})

 def test_atomic_write_replaces_without_leaving_a_temp_file(self):
  d=Path(tempfile.mkdtemp());p=d/"league-last.json"
  L.write_json_atomic(p,{"schema":1});L.write_json_atomic(p,{"schema":1,"complete":True})
  self.assertEqual(json.loads(p.read_text())["complete"],True)
  self.assertEqual([x.name for x in d.iterdir()],["league-last.json"])
 def test_atomic_write_creates_missing_parents(self):
  p=Path(tempfile.mkdtemp())/"runs"/"league-abc.json"
  L.write_json_atomic(p,{"run_id":"abc"});self.assertEqual(json.loads(p.read_text())["run_id"],"abc")


class LockTests(unittest.TestCase):
 def test_second_league_cannot_start_concurrently(self):
  """Two leagues writing league-last.json interleaved results and spend."""
  lock=Path(tempfile.mkdtemp())/"league.lock"
  self.assertTrue(L.acquire_lock(lock))
  self.assertFalse(L.acquire_lock(lock))
  L.release_lock(lock)
  self.assertTrue(L.acquire_lock(lock))
 def test_stale_lock_is_reclaimed(self):
  lock=Path(tempfile.mkdtemp())/"league.lock"
  self.assertTrue(L.acquire_lock(lock))
  old=time.time()-10_000;os.utime(lock,(old,old))
  self.assertTrue(L.acquire_lock(lock,stale=3600))
 def test_release_is_idempotent(self):
  lock=Path(tempfile.mkdtemp())/"league.lock"
  L.acquire_lock(lock);L.release_lock(lock);L.release_lock(lock)


class ScopeTests(unittest.TestCase):
 def test_no_changes_is_not_a_pass(self):
  self.assertFalse(L.check_scope([],{"a.js"}))
 def test_out_of_scope_path_voids_the_run(self):
  self.assertFalse(L.check_scope(["a.js","../etc/passwd"],{"a.js"}))
  self.assertFalse(L.check_scope(["test.js"],{"a.js"}))
 def test_in_scope_change_is_accepted(self):
  self.assertTrue(L.check_scope(["a.js"],{"a.js","b.js"}))

 def test_scrub_env_removes_provider_credentials(self):
  e=L.scrub_env({"PATH":"/bin","ANTHROPIC_API_KEY":"sk-x","GITHUB_TOKEN":"t","MY_SECRET":"s","HOME":"/h"})
  self.assertEqual(e,{"PATH":"/bin","HOME":"/h"})


@unittest.skipUnless(HAS_GIT,"git is required")
class FixtureIntegrityTests(unittest.TestCase):
 def make(self,cat="small_bug"):
  ws=Path(tempfile.mkdtemp())/"ws";return ws,fixtures.make(ws,cat)

 def test_test_js_is_not_writable_by_the_candidate(self):
  """test.js used to be in allowed_files, so a candidate could delete the
  assertions and 'pass' every benchmark."""
  for cat in fixtures.CATEGORIES:
   fx=fixtures.make(Path(tempfile.mkdtemp())/"ws",cat)
   self.assertNotIn("test.js",fx["allowed_files"],cat)
   self.assertIn("test.js",fx["packet"]["context_files"],cat)

 def test_unknown_category_raises(self):
  with self.assertRaises(fixtures.FixtureError):fixtures.make(Path(tempfile.mkdtemp())/"ws","nope")

 def test_fixture_records_a_base_commit_and_clean_tree(self):
  ws,fx=self.make()
  self.assertEqual(len(fx["base_commit"]),40)
  self.assertEqual(L.changed_paths(ws,fx["base_commit"]),[])

 def test_pristine_oracle_lives_outside_the_workspace(self):
  ws,fx=self.make();pristine=Path(fx["pristine_test"])
  self.assertFalse(str(pristine).startswith(str(ws)+os.sep),"candidate can reach the pristine oracle")
  self.assertEqual(fixtures.digest(pristine),fx["test_sha256"])
  self.assertEqual(fixtures.digest(ws/"test.js"),fx["test_sha256"])

 def test_rebuilding_a_workspace_in_place_is_clean(self):
  ws,_=self.make();(ws/"stale.js").write_text("//\n",encoding="utf-8")
  fx=fixtures.make(ws,"small_bug")
  self.assertFalse((ws/"stale.js").exists())
  self.assertEqual(L.changed_paths(ws,fx["base_commit"]),[])


@unittest.skipUnless(HAS_GIT,"git is required")
class ChangeDetectionTests(unittest.TestCase):
 def setUp(self):
  self.ws=Path(tempfile.mkdtemp())/"ws";self.fx=fixtures.make(self.ws,"small_bug");self.base=self.fx["base_commit"]
 def git(self,*a):
  return subprocess.run(["git",*a],cwd=str(self.ws),capture_output=True,text=True)

 def test_clean_fixture_reports_no_changes(self):
  self.assertEqual(L.changed_paths(self.ws,self.base),[])
 def test_uncommitted_edit_is_detected(self):
  (self.ws/"util.js").write_text("exports.last=a=>a[a.length-1]\n",encoding="utf-8")
  self.assertEqual(L.changed_paths(self.ws,self.base),["util.js"])
 def test_committed_work_is_still_attributed(self):
  """`git status` alone reported a clean tree for a candidate that committed
  its fix, scoring a correct solution as 'no changes' and a failure."""
  (self.ws/"util.js").write_text("exports.last=a=>a[a.length-1]\n",encoding="utf-8")
  self.git("add","-A");self.git("-c","commit.gpgsign=false","commit","-q","--no-verify","-m","fix")
  self.assertEqual(L.changed_paths(self.ws,self.base),["util.js"])
  self.assertTrue(L.check_scope(L.changed_paths(self.ws,self.base),self.fx["allowed_files"]))
 def test_committed_out_of_scope_edit_is_caught(self):
  (self.ws/"test.js").write_text("process.exit(0)\n",encoding="utf-8")
  self.git("add","-A");self.git("-c","commit.gpgsign=false","commit","-q","--no-verify","-m","cheat")
  paths=L.changed_paths(self.ws,self.base)
  self.assertIn("test.js",paths)
  self.assertFalse(L.check_scope(paths,self.fx["allowed_files"]))
 def test_untracked_file_is_detected(self):
  (self.ws/"sneaky.js").write_text("//\n",encoding="utf-8")
  self.assertIn("sneaky.js",L.changed_paths(self.ws,self.base))
 def test_untracked_file_in_a_subdirectory_is_detected(self):
  (self.ws/"sub").mkdir();(self.ws/"sub"/"x.js").write_text("//\n",encoding="utf-8")
  self.assertIn("sub/x.js",L.changed_paths(self.ws,self.base))
 def test_paths_with_spaces_are_not_quoted_or_split(self):
  """Without -z git quotes unusual paths, so the scope check compared a
  quoted string against allowed_files and mis-attributed the change."""
  (self.ws/"a file.js").write_text("//\n",encoding="utf-8")
  self.assertIn("a file.js",L.changed_paths(self.ws,self.base))
 def test_renamed_file_reports_both_sides(self):
  self.git("mv","util.js","renamed.js")
  paths=L.changed_paths(self.ws,self.base)
  self.assertIn("util.js",paths);self.assertIn("renamed.js",paths)
  self.assertFalse(L.check_scope(paths,self.fx["allowed_files"]))
 def test_deleted_file_is_detected(self):
  (self.ws/"test.js").unlink()
  self.assertIn("test.js",L.changed_paths(self.ws,self.base))
 def test_broken_repository_raises_instead_of_reporting_clean(self):
  """A failed `git status` returned an empty stdout, which read as 'no
  changes' rather than as an unknown workspace state."""
  import shutil as _sh;_sh.rmtree(self.ws/".git")
  with self.assertRaises(L.LeagueError):L.changed_paths(self.ws,self.base)
 def test_missing_base_commit_raises(self):
  with self.assertRaises(L.LeagueError):L.changed_paths(self.ws,"0"*40)

 def test_tampered_oracle_is_detected_by_digest(self):
  (self.ws/"test.js").write_text("process.exit(0)\n",encoding="utf-8")
  self.assertNotEqual(fixtures.digest(self.ws/"test.js"),self.fx["test_sha256"])
 def test_untouched_oracle_matches_its_digest(self):
  self.assertEqual(fixtures.digest(self.ws/"test.js"),self.fx["test_sha256"])


@unittest.skipUnless(HAS_GIT and HAS_NODE,"git and node are required")
class BenchmarkSanityTests(unittest.TestCase):
 """Each benchmark must actually be failing at t=0 and passable in scope."""
 def test_every_fixture_starts_red(self):
  for cat in fixtures.CATEGORIES:
   ws=Path(tempfile.mkdtemp())/"ws";fixtures.make(ws,cat)
   q=subprocess.run(["node","test.js"],cwd=str(ws),capture_output=True,text=True)
   self.assertNotEqual(q.returncode,0,f"{cat} benchmark already passes; it cannot score anything")
 def test_a_correct_in_scope_fix_passes(self):
  ws=Path(tempfile.mkdtemp())/"ws";fx=fixtures.make(ws,"small_bug")
  (ws/"util.js").write_text("exports.last=a=>a[a.length-1]\n",encoding="utf-8")
  paths=L.changed_paths(ws,fx["base_commit"])
  self.assertTrue(L.check_scope(paths,fx["allowed_files"]))
  self.assertEqual(subprocess.run(["node","test.js"],cwd=str(ws),capture_output=True).returncode,0)
 def test_refactor_cannot_be_won_by_a_cosmetic_edit(self):
  """The refactor oracle shipped green, so touching a.js with a comment was
  an in-scope 'pass' and could take the category."""
  ws=Path(tempfile.mkdtemp())/"ws";fx=fixtures.make(ws,"refactor")
  (ws/"a.js").write_text(fixtures.REFACTOR_SRC+"// tidied\n",encoding="utf-8")
  self.assertTrue(L.check_scope(L.changed_paths(ws,fx["base_commit"]),fx["allowed_files"]))
  self.assertNotEqual(subprocess.run(["node","test.js"],cwd=str(ws),capture_output=True).returncode,0)
 def test_refactor_is_won_by_the_real_deduplication(self):
  ws=Path(tempfile.mkdtemp())/"ws";fx=fixtures.make(ws,"refactor")
  (ws/"normalize.js").write_text(fixtures.REFACTOR_SRC,encoding="utf-8")
  for f in ("a.js","b.js"):(ws/f).write_text("exports.norm=require('./normalize').norm\n",encoding="utf-8")
  self.assertTrue(L.check_scope(L.changed_paths(ws,fx["base_commit"]),fx["allowed_files"]))
  self.assertEqual(subprocess.run(["node","test.js"],cwd=str(ws),capture_output=True).returncode,0)
 def test_deleting_the_oracle_cannot_manufacture_a_pass(self):
  ws=Path(tempfile.mkdtemp())/"ws";fx=fixtures.make(ws,"small_bug")
  (ws/"test.js").write_text("",encoding="utf-8")
  paths=L.changed_paths(ws,fx["base_commit"])
  self.assertFalse(L.check_scope(paths,fx["allowed_files"]),"emptied test.js passed the scope gate")
  self.assertNotEqual(fixtures.digest(ws/"test.js"),fx["test_sha256"])


class SnapshotTests(unittest.TestCase):
 def snap(self,**kw):
  d=dict(run_id="r1",target=1.0,started=0.,spent=.1,charged=.2,res=[],wins={},details={},notes={},complete=False);d.update(kw)
  return L._snapshot(d["run_id"],d["target"],d["started"],d["spent"],d["charged"],d["res"],d["wins"],d["details"],d["notes"],d["complete"])

 def test_dashboard_contract_is_preserved(self):
  """dashboard/server.py and pro_shell.py read winners{} and
  reported_measured_spend_usd; keep both shapes."""
  s=self.snap(wins={"auth":"mini-swe","ci":None})
  self.assertEqual(s["winners"],{"auth":"mini-swe","ci":None})
  self.assertIsInstance(s["reported_measured_spend_usd"],float)
  self.assertEqual(s["schema"],1);self.assertEqual(s["kind"],"category-league")
  self.assertEqual((s["github_writes"],s["merge"],s["deploy"]),(0,False,False))
 def test_partial_snapshot_is_flagged_incomplete(self):
  """A crash mid-round used to persist nothing at all; a partial record must
  be readable and must not look like a finished tournament."""
  self.assertFalse(self.snap(complete=False)["complete"])
  self.assertTrue(self.snap(complete=True)["complete"])
 def test_reported_and_charged_spend_are_reported_separately(self):
  s=self.snap(spent=.05,charged=.40)
  self.assertEqual(s["reported_measured_spend_usd"],.05);self.assertEqual(s["budget_charged_usd"],.40)
 def test_snapshot_survives_poisoned_rows(self):
  s=self.snap(res=[{"executor":"x","reported_cost_usd":float("nan")}])
  self.assertEqual(json.loads(L.dumps(s))["results"][0]["reported_cost_usd"],None)

 def test_every_candidate_gets_a_row_shape(self):
  """Skipped and lease-denied candidates were appended to a local list only
  and never reached `results`, so the report silently lost them."""
  r=L._blank_row("r1","auth","mini-swe",0)
  for k in ("run_id","category","executor","candidate_index","passed","scope_ok","budget_charged_usd"):
   self.assertIn(k,r)
  self.assertIs(r["passed"],False)
  self.assertIsNone(L.select_winner([r]))


class TournamentLoopTests(unittest.TestCase):
 """End-to-end `_run` with the real categories and a stubbed executor."""
 def setUp(self):
  self.state=Path(tempfile.mkdtemp());self._old=L.STATE;L.STATE=self.state
  self._oldrun=L.run_candidate
 def tearDown(self):
  L.STATE=self._old;L.run_candidate=self._oldrun

 def go(self,stub,target=1.0):
  L.run_candidate=stub
  import contextlib,io
  buf=io.StringIO()
  with contextlib.redirect_stdout(buf):rc=L._run(target,"testrun")
  return rc,json.loads((self.state/"league-last.json").read_text()),buf.getvalue()

 def passing(self,cost):
  def stub(cat,ex,alloc,env,seq):
   return {"status":"scored","passed":True,"scope_ok":True,"changed_paths":["x.js"],"reported_cost_usd":cost,"cost_status":"ok","budget_charged_usd":L.charge_for(cost,alloc),"worker_exit_code":0}
  return stub

 def test_full_tournament_designates_every_category(self):
  rc,doc,_=self.go(self.passing(.01))
  self.assertEqual(rc,0);self.assertTrue(doc["complete"])
  self.assertEqual(set(doc["winners"]),set(L.load_categories(L.HERE/"categories.json")))
  self.assertTrue(all(v for v in doc["winners"].values()))
  self.assertEqual(len(doc["results"]),doc["notes"]["candidate_count"])

 def test_every_candidate_appears_in_results_including_skips(self):
  """Skipped/denied candidates used to be dropped from `results` entirely."""
  def stub(cat,ex,alloc,env,seq):
   if seq%2:return {"status":"skipped","skipped":"ForgeBoss policy lease denied"}
   return self.passing(.01)(cat,ex,alloc,env,seq)
  _,doc,_=self.go(stub)
  self.assertEqual(len(doc["results"]),doc["notes"]["candidate_count"])
  self.assertTrue(any(r["status"]=="skipped" for r in doc["results"]))
  for r in doc["results"]:self.assertIn("category",r);self.assertIn("executor",r)

 def test_one_crashing_candidate_does_not_abort_the_tournament(self):
  """An unhandled exception in any candidate used to kill the process and
  discard every row collected so far."""
  def stub(cat,ex,alloc,env,seq):
   if cat=="auth":raise RuntimeError("boom")
   return self.passing(.01)(cat,ex,alloc,env,seq)
  rc,doc,_=self.go(stub)
  self.assertEqual(rc,0);self.assertTrue(doc["complete"])
  self.assertIsNone(doc["winners"]["auth"])
  self.assertTrue(all(doc["winners"][c] for c in doc["winners"] if c!="auth"))
  errs=[r for r in doc["results"] if r["status"]=="error"]
  self.assertTrue(errs);self.assertIn("boom",errs[0]["error"])

 def test_a_hung_candidate_is_recorded_and_charged(self):
  """subprocess.TimeoutExpired escaped and aborted the league; a timed-out
  paid call must still be charged against the budget."""
  def stub(cat,ex,alloc,env,seq):
   if seq==1:raise subprocess.TimeoutExpired("cmd",L.WORKER_TIMEOUT)
   return self.passing(.01)(cat,ex,alloc,env,seq)
  rc,doc,_=self.go(stub)
  self.assertEqual(rc,0)
  t=[r for r in doc["results"] if r["status"]=="timeout"]
  self.assertEqual(len(t),1);self.assertIs(t[0]["timed_out"],True);self.assertIs(t[0]["passed"],False)
  self.assertGreater(t[0]["budget_charged_usd"],0)

 def test_budget_reserve_stops_spending_and_records_the_skips(self):
  _,doc,_=self.go(self.passing(5.0))
  skipped=[r for r in doc["results"] if r.get("skipped")=="budget reserve"]
  self.assertTrue(skipped,"budget reserve never engaged")
  self.assertEqual(len(doc["results"]),doc["notes"]["candidate_count"])

 def test_unreported_cost_still_exhausts_the_budget(self):
  """Reporting nothing used to cost nothing, so a silent executor could run
  the entire field with the cap never engaging."""
  def stub(cat,ex,alloc,env,seq):
   return {"status":"scored","passed":True,"scope_ok":True,"reported_cost_usd":None,"cost_status":"missing","budget_charged_usd":L.charge_for(None,alloc),"worker_exit_code":0}
  _,doc,_=self.go(stub,target=L.MIN_TARGET)
  self.assertEqual(doc["reported_measured_spend_usd"],0.)
  self.assertGreater(doc["budget_charged_usd"],0.)

 def test_nan_cost_neither_poisons_spend_nor_the_persisted_file(self):
  def stub(cat,ex,alloc,env,seq):
   return {"status":"scored","passed":True,"scope_ok":True,"reported_cost_usd":float("nan"),"cost_status":"non_finite","budget_charged_usd":L.charge_for(None,alloc),"worker_exit_code":0}
  _,doc,out=self.go(stub)
  self.assertTrue(math.isfinite(doc["reported_measured_spend_usd"]))
  self.assertTrue(math.isfinite(doc["budget_charged_usd"]))
  self.assertNotIn("NaN",(self.state/"league-last.json").read_text())
  for line in out.splitlines():json.loads(line.split("=",1)[1] if line.startswith("FORGEBOSS_LEAGUE_RESULT=") else line)

 def test_partial_state_is_persisted_and_archived_per_run(self):
  """A crash mid-round must leave an attributable record, and league-last
  must not be the only copy (it is overwritten by the next league)."""
  seen=[]
  def stub(cat,ex,alloc,env,seq):
   seen.append(json.loads((self.state/"league-last.json").read_text())["complete"])
   return self.passing(.01)(cat,ex,alloc,env,seq)
  _,doc,_=self.go(stub)
  self.assertTrue(seen and not any(seen),"in-flight snapshots were marked complete")
  arch=self.state/"runs"/"league-testrun.json"
  self.assertTrue(arch.exists())
  self.assertEqual(json.loads(arch.read_text())["run_id"],"testrun")
 def test_rows_carry_the_run_id_for_attribution(self):
  _,doc,_=self.go(self.passing(.01))
  self.assertTrue(all(r["run_id"]=="testrun" for r in doc["results"]))
  self.assertTrue(all(d["run_id"]=="testrun" for d in doc["winner_details"].values() if "run_id" in d))


class MainGuardTests(unittest.TestCase):
 def test_bad_target_exits_nonzero_without_running(self):
  self.assertEqual(L.main(["run_league.py","free"]),2)
 def test_concurrent_league_is_refused(self):
  lock=L.STATE/"league.lock";L.STATE.mkdir(parents=True,exist_ok=True)
  self.assertTrue(L.acquire_lock(lock))
  try:self.assertEqual(L.main(["run_league.py","1"]),3)
  finally:L.release_lock(lock)


if __name__=="__main__":unittest.main(verbosity=2)
