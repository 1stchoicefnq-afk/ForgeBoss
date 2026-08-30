from __future__ import annotations
import sqlite3,tempfile,threading,unittest
from pathlib import Path
from forgeboss.control.idempotency import (
    IdempotencyConflict,IdempotencyInProgress,IdempotencyStateError,
    complete,install_schema,request_digest,reserve,
)

class IdempotencyV2Tests(unittest.TestCase):
    def setUp(self):
        self.td=tempfile.TemporaryDirectory();self.db=Path(self.td.name)/"idem.sqlite3"
        self.conn=sqlite3.connect(self.db);install_schema(self.conn);self.conn.commit()
        self.digest=request_digest("task.create",{"x":1})
    def tearDown(self):
        self.conn.close();self.td.cleanup()

    def test_cross_principal_same_key_never_replays_other_result(self):
        reserve(self.conn,"alice","task.create","same",self.digest);complete(self.conn,"alice","task.create","same",self.digest,{"taskId":"A"})
        r=reserve(self.conn,"bob","task.create","same",self.digest);self.assertFalse(r.replay);self.assertIsNone(r.result)

    def test_cross_operation_same_key_does_not_alias(self):
        d2=request_digest("task.cancel",{"x":1});reserve(self.conn,"alice","task.create","same",self.digest);complete(self.conn,"alice","task.create","same",self.digest,{"ok":1})
        self.assertFalse(reserve(self.conn,"alice","task.cancel","same",d2).replay)

    def test_same_identity_same_digest_replays_after_restart(self):
        reserve(self.conn,"alice","task.create","k",self.digest);complete(self.conn,"alice","task.create","k",self.digest,{"ok":True});self.conn.commit();self.conn.close()
        self.conn=sqlite3.connect(self.db);install_schema(self.conn);r=reserve(self.conn,"alice","task.create","k",self.digest)
        self.assertTrue(r.replay);self.assertEqual(r.result,{"ok":True})

    def test_same_identity_different_digest_conflicts(self):
        reserve(self.conn,"alice","task.create","k",self.digest)
        with self.assertRaises(IdempotencyConflict):reserve(self.conn,"alice","task.create","k","b"*64)

    def test_safe_result_redacts_nested_tokens_and_secrets(self):
        reserve(self.conn,"alice","task.create","k",self.digest);complete(self.conn,"alice","task.create","k",self.digest,{"ok":True,"accessToken":"secret-value","nested":{"api_key":"abc","value":3},"list":[{"refresh_token":"xyz"},{"safe":"yes"}]})
        raw=self.conn.execute("select result_json from idempotency_operations").fetchone()[0]
        self.assertNotIn("secret-value",raw);self.assertNotIn('"abc"',raw);self.assertNotIn('"xyz"',raw)
        r=reserve(self.conn,"alice","task.create","k",self.digest);self.assertEqual(r.result["accessToken"],"[REDACTED]");self.assertEqual(r.result["nested"]["api_key"],"[REDACTED]");self.assertEqual(r.result["list"][0]["refresh_token"],"[REDACTED]")

    def test_persisted_replay_json_rejects_duplicate_nonfinite_and_secret(self):
        for idx,bad in enumerate(['{"a":1,"a":2}','{"x":NaN}','{"accessToken":"plaintext"}']):
            with self.subTest(bad=bad):
                key=f"k{idx}";reserve(self.conn,"alice","task.create",key,self.digest)
                self.conn.execute("update idempotency_operations set state='completed',result_json=? where principal_id='alice' and operation='task.create' and idempotency_key=?",(bad,key))
                with self.assertRaises(IdempotencyStateError):reserve(self.conn,"alice","task.create",key,self.digest)

    def test_rollback_leaves_no_ghost_reservation(self):
        self.conn.execute("BEGIN");reserve(self.conn,"alice","task.create","rollback",self.digest);self.conn.rollback()
        self.assertEqual(self.conn.execute("select count(*) from idempotency_operations where idempotency_key='rollback'").fetchone()[0],0)
        self.assertFalse(reserve(self.conn,"alice","task.create","rollback",self.digest).replay)

    def test_double_completion_and_unknown_reservation_fail_closed(self):
        reserve(self.conn,"alice","task.create","k",self.digest);complete(self.conn,"alice","task.create","k",self.digest,{"ok":1})
        with self.assertRaises(IdempotencyStateError):complete(self.conn,"alice","task.create","k",self.digest,{"ok":2})
        with self.assertRaises(IdempotencyStateError):complete(self.conn,"alice","task.create","missing",self.digest,{"ok":1})

    def test_unknown_persisted_state_fails_closed(self):
        reserve(self.conn,"alice","task.create","k",self.digest);self.conn.execute("update idempotency_operations set state='mystery' where idempotency_key='k'")
        with self.assertRaises(IdempotencyStateError):reserve(self.conn,"alice","task.create","k",self.digest)

    def test_concurrent_same_identity_has_single_reservation(self):
        self.conn.close();barrier=threading.Barrier(2);results=[];lock=threading.Lock()
        def worker():
            c=sqlite3.connect(self.db,timeout=3);install_schema(c);barrier.wait()
            try:out=reserve(c,"alice","task.create","race",self.digest);c.commit();v=("ok",out.replay)
            except Exception as ex:c.rollback();v=("err",type(ex).__name__)
            finally:c.close()
            with lock:results.append(v)
        a=threading.Thread(target=worker);b=threading.Thread(target=worker);a.start();b.start();a.join();b.join();self.conn=sqlite3.connect(self.db)
        self.assertEqual(sum(x[0]=="ok" for x in results),1);self.assertEqual(sum(x[1]=="IdempotencyInProgress" for x in results if x[0]=="err"),1)
        self.assertEqual(self.conn.execute("select count(*) from idempotency_operations where idempotency_key='race'").fetchone()[0],1)

if __name__=="__main__":unittest.main()
