from __future__ import annotations

import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from forgeboss.control.activation import (
    ActivationError,
    ActivationManager,
    _atomic_json,
    _same_process,
    candidate_probe_proof,
    process_identity,
)


def _restart_adoption_worker(state_dir, identity, ready, go, hold, out):
    try:
        runtime = process_identity(os.getpid())
        m = ActivationManager(state_dir, identity, runtime)
        ready.put(os.getpid())
        go.wait(10)
        m.recover()
        out.put(("OK", os.getpid()))
        hold.wait(10)
    except Exception as ex:
        out.put(("ERR", os.getpid(), type(ex).__name__, str(ex)))


class ActivationTests(unittest.TestCase):
    def _identity(self, root, revision="1" * 40, verified=True, digest="3" * 64):
        return {
            "verified": verified,
            "revision": revision if verified else None,
            "codeRoot": str(root.resolve()),
            "entrypoint": "forgeboss/daemon.py",
            "manifestPath": str(root / "manifest.json"),
            "manifestSha256": "2" * 64 if verified else None,
            "identitySha256": digest if verified else None,
            "treeSha256": "4" * 64 if verified else None,
            "files": {},
        }

    def _manager(self, base, verified=True):
        running = base / "running"
        running.mkdir()
        return ActivationManager(
            base / "state",
            self._identity(running, verified=verified),
            {"pid": 111, "startToken": "prior", "exe": "python"},
        )

    def _stage(self, m, base, revision="a" * 40):
        root = base / "candidate"
        pkg = root / "forgeboss"
        pkg.mkdir(parents=True)
        (pkg / "daemon.py").write_text("print('candidate')\n", encoding="utf-8")
        manifest = base / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        c = {
            "verified": True,
            "revision": revision,
            "codeRoot": str(root.resolve()),
            "entrypoint": "forgeboss/daemon.py",
            "manifestPath": str(manifest.resolve()),
            "manifestSha256": "5" * 64,
            "identitySha256": "6" * 64,
            "treeSha256": "7" * 64,
            "files": {"forgeboss/daemon.py": "8" * 64},
        }
        with patch("forgeboss.control.activation.verify_build_manifest", return_value=c), patch(
            "forgeboss.control.activation.process_is_same_and_alive", return_value=True
        ):
            return m.stage(root, manifest, revision, "5" * 64)

    def _start(self, m, cp):
        fake = Mock(pid=cp["pid"])
        popen = Mock(return_value=fake)
        with patch("forgeboss.control.activation.subprocess.Popen", popen), patch(
            "forgeboss.control.activation.process_identity", return_value=cp
        ), patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
            m.start_candidate([])
            m.begin_probe()
        return popen

    def _genuine_result(self, m, staged, cp, popen):
        result = {
            "startup": True,
            "health": True,
            "control": True,
            "selftests": True,
            "multiAgent": True,
            "identity": {
                "revision": staged["candidate"]["revision"],
                "manifestSha256": staged["candidate"]["manifestSha256"],
                "identitySha256": staged["candidate"]["identitySha256"],
            },
        }
        env = popen.call_args.kwargs["env"]
        with patch.dict(os.environ, env, clear=False), patch(
            "forgeboss.control.activation.process_identity", return_value=cp
        ):
            result["proof"] = candidate_probe_proof(result)
        return result

    def _promote(self, m, base):
        staged = self._stage(m, base)
        cp = {"pid": 222, "startToken": "cand", "exe": "python"}
        popen = self._start(m, cp)
        result = self._genuine_result(m, staged, cp, popen)
        with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
            m.record_probe(result)
            m.promote()
        return cp

    def test_unverified_running_controller_cannot_stage(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b, False)
            r = b / "candidate"
            r.mkdir()
            f = b / "m"
            f.write_text("{}")
            with self.assertRaises(ActivationError):
                m.stage(r, f)

    def test_pid_reuse_mismatch_is_not_same_process(self):
        self.assertFalse(
            _same_process(
                {"pid": 10, "startToken": "old", "exe": "python"},
                {"pid": 10, "startToken": "new", "exe": "python"},
            )
        )

    def test_genuine_candidate_probe_succeeds_once(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b)
            staged = self._stage(m, b)
            cp = {"pid": 222, "startToken": "cand", "exe": "python"}
            popen = self._start(m, cp)
            result = self._genuine_result(m, staged, cp, popen)
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                self.assertEqual(m.record_probe(result)["phase"], "PROBED")
                with self.assertRaises(ActivationError):
                    m.record_probe(result)

    def test_wrong_mac_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b)
            staged = self._stage(m, b)
            cp = {"pid": 222, "startToken": "cand", "exe": "python"}
            popen = self._start(m, cp)
            result = self._genuine_result(m, staged, cp, popen)
            result["proof"]["mac"] = "0" * 64
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                with self.assertRaisesRegex(ActivationError, "authentication failed"):
                    m.record_probe(result)

    def test_wrong_nonce_process_and_build_identity_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b)
            staged = self._stage(m, b)
            cp = {"pid": 222, "startToken": "cand", "exe": "python"}
            popen = self._start(m, cp)
            base = self._genuine_result(m, staged, cp, popen)
            variants = []
            wrong_nonce = {**base, "proof": dict(base["proof"])}
            wrong_nonce["proof"]["activationNonce"] = "bad"
            variants.append(wrong_nonce)
            wrong_proc = {**base, "proof": dict(base["proof"])}
            wrong_proc["proof"]["processIdentity"] = {"pid": 222, "startToken": "other", "exe": "python"}
            variants.append(wrong_proc)
            wrong_identity = {**base, "identity": dict(base["identity"]), "proof": dict(base["proof"])}
            wrong_identity["identity"]["identitySha256"] = "9" * 64
            variants.append(wrong_identity)
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                for item in variants:
                    with self.assertRaises(ActivationError):
                        m.record_probe(item)

    def test_stale_activation_and_lost_secret_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b)
            staged = self._stage(m, b)
            cp = {"pid": 222, "startToken": "cand", "exe": "python"}
            popen = self._start(m, cp)
            result = self._genuine_result(m, staged, cp, popen)
            restarted = ActivationManager(b / "state", m.running_identity, m.runtime_process_identity)
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                with self.assertRaisesRegex(ActivationError, "authentication context unavailable"):
                    restarted.record_probe(result)

    def test_cross_candidate_proof_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b1 = Path(td) / "one"
            b2 = Path(td) / "two"
            b1.mkdir()
            b2.mkdir()
            m1 = self._manager(b1)
            s1 = self._stage(m1, b1)
            cp1 = {"pid": 222, "startToken": "cand1", "exe": "python"}
            p1 = self._start(m1, cp1)
            proof1 = self._genuine_result(m1, s1, cp1, p1)
            m2 = self._manager(b2)
            s2 = self._stage(m2, b2, "b" * 40)
            cp2 = {"pid": 333, "startToken": "cand2", "exe": "python"}
            self._start(m2, cp2)
            proof1["proof"]["processIdentity"] = cp2
            proof1["identity"] = {
                "revision": s2["candidate"]["revision"],
                "manifestSha256": s2["candidate"]["manifestSha256"],
                "identitySha256": s2["candidate"]["identitySha256"],
            }
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                with self.assertRaises(ActivationError):
                    m2.record_probe(proof1)

    def test_candidate_denied_before_promotion(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b)
            self._stage(m, b)
            c = self._identity(b / "candidate", "a" * 40, digest="6" * 64)
            cp = {"pid": 222, "startToken": "cand", "exe": "python"}
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                with self.assertRaises(ActivationError):
                    m.assert_mutation_authority(c, cp)

    def test_promotion_transfers_authority(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b)
            cp = self._promote(m, b)
            c = m.status()["candidate"]
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                with self.assertRaises(ActivationError):
                    m.assert_mutation_authority(m.running_identity, m.runtime_process_identity)
                self.assertTrue(m.assert_mutation_authority(c, cp))

    def test_promoted_health_only_requests_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            prior = self._manager(b)
            cp = self._promote(prior, b)
            c = prior.status()["candidate"]
            candidate = ActivationManager(b / "state", c, cp)
            pending = candidate.activation_health(False)
            self.assertEqual(pending["phase"], "ROLLBACK_PENDING")
            with self.assertRaisesRegex(ActivationError, "only prior known-good identity"):
                candidate.finalize_rollback()
            self.assertEqual(prior.status()["phase"], "ROLLBACK_PENDING")

    def test_prior_finalizes_promoted_health_only_after_death_proof(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            prior = self._manager(b)
            cp = self._promote(prior, b)
            c = prior.status()["candidate"]
            ActivationManager(b / "state", c, cp).activation_health(False)
            with patch("forgeboss.control.activation.terminate_verified_process", return_value=True) as term:
                pointer = prior.finalize_rollback()
            term.assert_called_once_with(cp, 5.0)
            self.assertEqual(prior.status()["phase"], "ROLLED_BACK")
            self.assertEqual(pointer["current"]["identitySha256"], prior.running_identity["identitySha256"])

    def test_unverifiable_death_quarantines_without_restore(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            prior = self._manager(b)
            cp = self._promote(prior, b)
            c = prior.status()["candidate"]
            promoted = prior.known_good_pointer()
            ActivationManager(b / "state", c, cp).activation_health(False)
            with patch("forgeboss.control.activation.terminate_verified_process", return_value=False):
                with self.assertRaisesRegex(ActivationError, "death not proven"):
                    prior.finalize_rollback()
            self.assertEqual(prior.status()["phase"], "QUARANTINED")
            self.assertEqual(prior.known_good_pointer()["current"]["identitySha256"], promoted["current"]["identitySha256"])

    def test_crash_in_rollback_pending_recovered_by_prior(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            prior = self._manager(b)
            cp = self._promote(prior, b)
            c = prior.status()["candidate"]
            ActivationManager(b / "state", c, cp).activation_health(False)
            rp = {"pid": 333, "startToken": "prior2", "exe": "python"}
            restarted = ActivationManager(b / "state", prior.running_identity, rp)
            with patch("forgeboss.control.activation.process_is_same_and_alive", side_effect=lambda p: p == rp), patch(
                "forgeboss.control.activation.terminate_verified_process", return_value=True
            ):
                pointer = restarted.recover()
            self.assertEqual(restarted.status()["phase"], "ROLLED_BACK")
            self.assertEqual(pointer["current"]["identitySha256"], prior.running_identity["identitySha256"])

    def test_concurrent_two_process_restart_adoption_one_winner(self):
        ctx = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            sd = b / "state"
            sd.mkdir()
            cr = b / "candidate"
            cr.mkdir()
            pr = b / "prior"
            pr.mkdir()
            c = self._identity(cr, "a" * 40, digest="6" * 64)
            p = self._identity(pr, "1" * 40, digest="3" * 64)
            dead = {"pid": 999999, "startToken": "dead", "exe": "python"}
            _atomic_json(
                sd / "activation.json",
                {
                    "schema": 4,
                    "phase": "PROMOTED",
                    "prior": p,
                    "priorProcessIdentity": None,
                    "candidate": c,
                    "processIdentity": dead,
                    "pid": dead["pid"],
                    "pointer": {"schema": 4, "current": c, "previous": p, "promotedAt": 1.0},
                },
            )
            ready = ctx.Queue()
            out = ctx.Queue()
            go = ctx.Event()
            hold = ctx.Event()
            workers = [ctx.Process(target=_restart_adoption_worker, args=(str(sd), c, ready, go, hold, out)) for _ in range(2)]
            for w in workers:
                w.start()
            ready.get(timeout=10)
            ready.get(timeout=10)
            go.set()
            results = [out.get(timeout=10), out.get(timeout=10)]
            hold.set()
            for w in workers:
                w.join(10)
            self.assertEqual(sum(1 for r in results if r[0] == "OK"), 1)
            self.assertEqual(sum(1 for r in results if r[0] == "ERR"), 1)

    def test_failed_prepromotion_rollback_preserves_prior(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            m = self._manager(b)
            self._stage(m, b)
            fake = Mock(pid=222)
            pi = {"pid": 222, "startToken": "cand", "exe": "python"}
            with patch("forgeboss.control.activation.subprocess.Popen", return_value=fake), patch(
                "forgeboss.control.activation.process_identity", return_value=pi
            ), patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                m.start_candidate([])
            with patch("forgeboss.control.activation.terminate_verified_process", return_value=True):
                m.rollback("forced")
            self.assertEqual(m.status()["phase"], "ROLLED_BACK")
            with patch("forgeboss.control.activation.process_is_same_and_alive", return_value=True):
                self.assertTrue(m.assert_mutation_authority(m.running_identity, m.runtime_process_identity))


if __name__ == "__main__":
    unittest.main()
