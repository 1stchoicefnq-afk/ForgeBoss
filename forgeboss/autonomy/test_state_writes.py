from __future__ import annotations
import json,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import forgeboss.autonomy.repair_memory as rm
import forgeboss.autonomy.debug_funnel as dfn
import forgeboss.autonomy.evidence_collector as ec
import forgeboss.autonomy.failure_feedback as ff

class RepairMemoryCorruptDbTests(unittest.TestCase):
    # repair-memory.json is the record of which failure signatures already proved
    # dead ends and which strategies already proved out. If it is silently treated
    # as empty on corruption, the caller will pay to repeat known-failed (or
    # already-proven) paid work. It must fail closed instead.
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp())
        self.old_mem=rm.MEM
        rm.MEM=self.tmp/'repair-memory.json'
        rm.MEM.write_text('{not valid json',encoding='utf-8')

    def tearDown(self):
        rm.MEM=self.old_mem

    def write(self,name,obj):
        p=self.tmp/name;p.write_text(json.dumps(obj),encoding='utf-8');return p

    def test_recording_feedback_raises_on_corrupt_db(self):
        feedback=self.write('feedback.json',{"signature":"sig","category":"backend","acceptance":{"failed_steps":[]}})
        with mock.patch('sys.argv',['repair_memory.py','--feedback',str(feedback)]):
            with self.assertRaises(RuntimeError):
                rm.main()
        self.assertFalse(rm.MEM.exists())
        quarantined=list(self.tmp.glob('repair-memory.json.corrupt-*'))
        self.assertEqual(len(quarantined),1)
        self.assertEqual(quarantined[0].read_text(encoding='utf-8'),'{not valid json')

    def test_query_raises_on_corrupt_db_instead_of_reporting_empty_history(self):
        query=self.write('query.json',{"category":"backend","failure_signature":"sig"})
        with mock.patch('sys.argv',['repair_memory.py','--query',str(query)]):
            with self.assertRaises(RuntimeError):
                rm.main()

    def test_missing_db_is_treated_as_fresh_start_not_corruption(self):
        rm.MEM.unlink()
        feedback=self.write('feedback.json',{"signature":"sig","category":"backend","acceptance":{"failed_steps":[]}})
        with mock.patch('sys.argv',['repair_memory.py','--feedback',str(feedback)]):
            rm.main()
        self.assertEqual(json.loads(rm.MEM.read_text())['entries'][0]['signature'],'sig')


class RepairMemoryAtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp())
        self.old_mem=rm.MEM
        rm.MEM=self.tmp/'repair-memory.json'

    def tearDown(self):
        rm.MEM=self.old_mem

    def test_write_leaves_no_tmp_file_and_db_is_valid_json(self):
        feedback=self.tmp/'feedback.json'
        feedback.write_text(json.dumps({"signature":"sig","category":"backend","acceptance":{"failed_steps":[]}}),encoding='utf-8')
        with mock.patch('sys.argv',['repair_memory.py','--feedback',str(feedback)]):
            rm.main()
        self.assertTrue(rm.MEM.exists())
        self.assertEqual(list(self.tmp.glob('*.tmp')),[])
        self.assertEqual(json.loads(rm.MEM.read_text())['entries'][0]['signature'],'sig')


class DebugFunnelAtomicWriteTests(unittest.TestCase):
    # No local_workspace/source_repo in the feedback packet means resolve_repo()
    # short-circuits to None, so main() never shells out to git for this fixture.
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp())
        self.old_state=dfn.STATE
        dfn.STATE=self.tmp

    def tearDown(self):
        dfn.STATE=self.old_state

    def test_write_leaves_no_tmp_file_and_output_is_valid_json(self):
        feedback=self.tmp/'feedback.json'
        feedback.write_text(json.dumps({"target_sha":"abc123","signature":"sig","acceptance":{"evidence":[],"failed_steps":["step1"]}}),encoding='utf-8')
        with mock.patch('sys.argv',['debug_funnel.py','--feedback',str(feedback)]):
            dfn.main()
        out=self.tmp/'debug-funnel-last.json'
        self.assertTrue(out.exists())
        self.assertEqual([p for p in self.tmp.glob('*.tmp')],[])
        self.assertEqual(json.loads(out.read_text())['target_sha'],'abc123')


class EvidenceCollectorAtomicWriteTests(unittest.TestCase):
    # No local_workspace in the report means resolve_repo() returns None, so
    # main() never shells out to git for this fixture.
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp())
        self.old_state=ec.STATE
        ec.STATE=self.tmp

    def tearDown(self):
        ec.STATE=self.old_state

    def test_write_leaves_no_tmp_file_and_output_is_valid_json(self):
        report=self.tmp/'report.json'
        report.write_text(json.dumps({"exact_head":"abc123","attempts":[{"model_summary":"","reasoning_summary":""}]}),encoding='utf-8')
        with mock.patch('sys.argv',['evidence_collector.py','--report',str(report)]):
            ec.main()
        out=self.tmp/'evidence-enrichment-last.json'
        self.assertTrue(out.exists())
        self.assertEqual([p for p in self.tmp.glob('*.tmp')],[])
        self.assertEqual(json.loads(out.read_text())['exact_head'],'abc123')


class FailureFeedbackAtomicWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp=Path(tempfile.mkdtemp())
        self.old_state=ff.STATE
        ff.STATE=self.tmp

    def tearDown(self):
        ff.STATE=self.old_state

    def test_write_leaves_no_tmp_file_and_output_is_valid_json(self):
        source=self.tmp/'repair-rat.json'
        source.write_text(json.dumps({"exact_head":"abc123","attempts":[{"passed":False}]}),encoding='utf-8')
        ff.make(source,'repair-rat')
        out=self.tmp/'failure-feedback-last.json'
        self.assertTrue(out.exists())
        self.assertEqual([p for p in self.tmp.glob('*.tmp')],[])
        self.assertEqual(json.loads(out.read_text())['target_sha'],'abc123')


if __name__=='__main__':
    unittest.main()
