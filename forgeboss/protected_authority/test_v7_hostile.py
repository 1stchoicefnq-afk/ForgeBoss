from __future__ import annotations

import json,os,threading,time,unittest
from forgeboss.protected_authority.protocol import AuthorityError,MAX_REQUEST_BYTES
from forgeboss.protected_authority.lifecycle import LinuxAuthorityDaemon
from forgeboss.protected_authority.signing import verify_signed_receipt
from forgeboss.protected_authority.test_v7 import LinuxAvailabilityV7Tests,_request

@unittest.skipIf(os.name=='nt','native Unix hostile proof')
class LinuxOversizeV7Tests(unittest.TestCase):
    def test_oversized_client_cannot_starve_valid_signed_peer(self):
        helper=LinuxAvailabilityV7Tests();base,root,endpoint=helper._tree()
        try:
            svc,boundary,peer,receipt_pub=helper._service(root)
            daemon=LinuxAuthorityDaemon(service=svc,boundary=boundary,protected_root=root,endpoint_dir=endpoint,allowed_gid=os.getegid(),max_workers=2,preauth_timeout=0.75,accept_poll=0.05)
            server=threading.Thread(target=daemon.run_forever);server.start();deadline=time.monotonic()+3
            while not daemon.path.exists():
                if time.monotonic()>=deadline:self.fail('daemon socket missing')
                time.sleep(0.01)
            bad=helper._connect(daemon.path);bad_done=threading.Event()
            def flood():
                try:bad.sendall(b'x'*(MAX_REQUEST_BYTES+1));bad.shutdown(1)
                except OSError:pass
                finally:bad_done.set()
            attacker=threading.Thread(target=flood);attacker.start()
            try:
                started=time.monotonic();raw=helper._roundtrip(daemon.path,_request(peer));elapsed=time.monotonic()-started
                self.assertLess(elapsed,0.75);obj=json.loads(raw.decode());self.assertTrue(verify_signed_receipt(obj,receipt_pub));self.assertTrue(bad_done.wait(1.5))
                second=json.loads(helper._roundtrip(daemon.path,_request(peer)).decode());self.assertTrue(verify_signed_receipt(second,receipt_pub))
            finally:
                try:bad.close()
                except OSError:pass
                daemon.stop();server.join(2);attacker.join(1)
            self.assertFalse(server.is_alive())
        finally:
            __import__('shutil').rmtree(base,ignore_errors=True)

    def test_postauth_blocking_backend_shutdown_fails_closed_and_blocks_restart(self):
        helper=LinuxAvailabilityV7Tests();base,root,endpoint=helper._tree()
        release=threading.Event();entered=threading.Event();client_done=threading.Event()
        try:
            svc,boundary,peer,_=helper._service(root);original=svc.backend
            class BlockingBackend:
                def read_github_control(self,**kw):
                    entered.set();release.wait(5);return original.read_github_control(**kw)
                def publish_report_comment(self,**kw):return original.publish_report_comment(**kw)
                def publish_reviewed_draft_pr(self,**kw):return original.publish_reviewed_draft_pr(**kw)
                def verify_launch_authority(self,**kw):return original.verify_launch_authority(**kw)
            svc.backend=BlockingBackend()
            daemon=LinuxAuthorityDaemon(service=svc,boundary=boundary,protected_root=root,endpoint_dir=endpoint,allowed_gid=os.getegid(),max_workers=2,preauth_timeout=0.10,accept_poll=0.02)
            daemon.start();workers=[threading.Thread(target=daemon._worker_loop,daemon=True) for _ in range(2)];daemon._workers=workers
            for worker in workers:worker.start()
            def client():
                try:helper._roundtrip(daemon.path,_request(peer))
                except OSError:pass
                finally:client_done.set()
            caller=threading.Thread(target=client,daemon=True);caller.start()
            self.assertTrue(entered.wait(2),'backend did not reach post-auth blocking point')
            with self.assertRaises(AuthorityError) as cm:daemon.close()
            self.assertEqual(cm.exception.code,'IPC_WORKER_STUCK')
            self.assertTrue(any(worker.is_alive() for worker in daemon._workers))
            with daemon._active_lock:self.assertTrue(daemon._active)
            with self.assertRaises(AuthorityError) as cm2:daemon.start()
            self.assertEqual(cm2.exception.code,'IPC_WORKER_STUCK')
            release.set();caller.join(2)
            for worker in workers:worker.join(2)
            self.assertTrue(client_done.is_set())
            daemon.close();self.assertEqual(daemon._workers,[])
            with daemon._active_lock:self.assertFalse(daemon._active)
        finally:
            release.set();__import__('shutil').rmtree(base,ignore_errors=True)

if __name__=='__main__':unittest.main()
