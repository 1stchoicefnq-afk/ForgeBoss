from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest

from forgeboss.control.governed_supervisor import (
    _BoundedText,
    _kill_tree,
    _tree_alive,
    _validated_openai_credentials,
    GovernedSupervisorError,
)


class GovernedSupervisorTests(unittest.TestCase):
    def test_bounded_output_keeps_tail(self):
        b=_BoundedText(10)
        b.append("12345")
        b.append("67890")
        b.append("ABCDE")
        self.assertEqual(b.value(),"67890ABCDE")

    def test_invalid_poll_interval_fails_closed_without_launch(self):
        class D: pass
        with self.assertRaises(GovernedSupervisorError):
            from forgeboss.control.governed_supervisor import supervise_governed_run
            supervise_governed_run(
                D(), task_id="T", packet_path="missing", workspace_path="missing",
                allowed_tools=[], adapter="mini-swe", provider="openai", model="openai/m",
                budget_usd=1, poll_seconds=0, credential_env={"OPENAI_API_KEY":"x"},
            )

    def test_non_miniswe_is_not_supported_in_r0(self):
        class D: pass
        with self.assertRaisesRegex(GovernedSupervisorError,"mini-swe only"):
            from forgeboss.control.governed_supervisor import supervise_governed_run
            supervise_governed_run(
                D(), task_id="T", packet_path="missing", workspace_path="missing",
                allowed_tools=[], adapter="openhands", provider="openai", model="openai/m",
                budget_usd=1, credential_env={"OPENAI_API_KEY":"x"},
            )

    def test_r0_credential_is_bound_to_openai_provider_and_model_prefix(self):
        self.assertEqual(
            _validated_openai_credentials(
                "openai","openai/gpt-5.6-luna",{"OPENAI_API_KEY":"secret"}
            ),
            {"OPENAI_API_KEY":"secret"},
        )
        bad_cases=[
            ("anthropic","openai/gpt-5.6-luna",{"OPENAI_API_KEY":"secret"}),
            ("openai","anthropic/claude",{"OPENAI_API_KEY":"secret"}),
            ("openai","openai/gpt-5.6-luna",{"ANTHROPIC_API_KEY":"secret"}),
            ("openai","openai/gpt-5.6-luna",{"OPENAI_API_KEY":"secret","LLM_API_KEY":"other"}),
            ("openai","openai/gpt-5.6-luna",{"OPENAI_API_KEY":""}),
        ]
        for provider,model,creds in bad_cases:
            with self.subTest(provider=provider,model=model,keys=sorted(creds)):
                with self.assertRaises(GovernedSupervisorError):
                    _validated_openai_credentials(provider,model,creds)

    @unittest.skipIf(os.name=="nt","POSIX process-group regression")
    def test_parent_exit_does_not_hide_live_descendant_group(self):
        code=(
            "import subprocess,sys;"
            "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "print('spawned',flush=True)"
        )
        proc=subprocess.Popen(
            [sys.executable,"-c",code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.addCleanup(lambda: _kill_tree(proc))
        self.assertEqual(proc.stdout.readline().strip(),"spawned")
        proc.wait(timeout=5)
        self.assertTrue(_tree_alive(proc))
        _kill_tree(proc)
        deadline=time.time()+3
        while _tree_alive(proc) and time.time()<deadline:
            time.sleep(0.05)
        self.assertFalse(_tree_alive(proc))


if __name__=="__main__":
    unittest.main()
