from __future__ import annotations

import os,threading,time,unittest
from forgeboss.protected_authority.protocol import MAX_REQUEST_BYTES
from forgeboss.protected_authority.lifecycle import LinuxAuthorityDaemon
from forgeboss.protected_authority.signing import verify_signed_receipt
from forgeboss.protected_authority.test_v7 import LinuxAvailabilityV7Tests,_request
import json

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

if __name__=='__main__':unittest.main()
