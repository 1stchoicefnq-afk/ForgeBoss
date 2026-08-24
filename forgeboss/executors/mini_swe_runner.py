from __future__ import annotations
import json, math, os, sys, subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _positive_budget(raw):
    if isinstance(raw, bool):
        raise ValueError("budget must be a finite positive number")
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError) as ex:
        raise ValueError("budget must be a finite positive number") from ex
    if not math.isfinite(value) or value <= 0:
        raise ValueError("budget must be a finite positive number")
    return value


def _observed_cost(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) and result >= 0 else None


def _consume_executor_budget(packet_path, workspace, cli_budget):
    lease = os.environ.get("FORGEBOSS_EXECUTOR_LEASE", "")
    lease_token = os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN", "")
    control_envelope = os.environ.get("FORGEBOSS_CONTROL_ENVELOPE", "")
    if not lease or not lease_token or not control_envelope:
        raise PermissionError("paid executor authority is incomplete")
    guard = ROOT / "forgeboss" / "security" / "executor_guard.py"
    proc = subprocess.run(
        [
            sys.executable,
            str(guard),
            "consume",
            "--lease",
            lease,
            "--token",
            lease_token,
            "--packet",
            str(packet_path),
            "--workspace",
            str(workspace),
            "--executor",
            "mini-swe",
            "--control-envelope",
            control_envelope,
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode:
        raise PermissionError("executor lease consumption denied: " + (proc.stdout or proc.stderr)[-1200:])
    lines = [line for line in (proc.stdout or "").splitlines() if line.strip()]
    if not lines:
        raise PermissionError("executor lease consumption returned no authority")
    try:
        payload = json.loads(lines[-1])
    except Exception as ex:
        raise PermissionError("executor lease consumption returned invalid authority") from ex
    if payload.get("ok") is not True or payload.get("consumed") is not True:
        raise PermissionError("executor lease was not consumed")
    budget = _positive_budget(payload.get("budget_usd"))
    cli = _positive_budget(cli_budget)
    if cli != budget:
        raise PermissionError(f"runner budget {cli} differs from consumed lease authority {budget}")
    return budget


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: mini_swe_runner.py PACKET.json WORKSPACE BUDGET_USD", file=sys.stderr)
        return 2
    if os.environ.get("FORGEBOSS_ALLOW_PAID_EXECUTOR") != "YES":
        print("FORGEBOSS SAFE STOP: paid executor gate is not enabled.")
        return 3

    packet_path = Path(sys.argv[1])
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    workspace = str(Path(sys.argv[2]).resolve())
    try:
        consumed_budget = _consume_executor_budget(packet_path, workspace, sys.argv[3])
    except Exception as ex:
        print("FORGEBOSS SAFE STOP: " + str(ex), file=sys.stderr)
        return 12

    model_name = os.environ.get("FORGEBOSS_MINISWE_MODEL", "openai/gpt-5.6-luna")
    result = {"executor": "mini-swe", "model": model_name, "cost_usd": None, "completed": False, "error": None}
    guard = ROOT / "forgeboss" / "security" / "executor_guard.py"
    lease = os.environ.get("FORGEBOSS_EXECUTOR_LEASE", "")
    lease_token = os.environ.get("FORGEBOSS_EXECUTOR_LEASE_TOKEN", "")
    env_obj = None

    try:
        from minisweagent.agents.default import DefaultAgent
        from minisweagent.environments.docker import DockerEnvironment
        from minisweagent.models.litellm_model import LitellmModel

        mount = f"type=bind,src={workspace},dst=/workspace"
        env_obj = DockerEnvironment(
            image=os.environ.get("FORGEBOSS_MINISWE_IMAGE", "node:22-bookworm"),
            cwd="/workspace",
            run_args=["--rm", "--network", "none", "--mount", mount],
            timeout=180,
            container_timeout="45m",
        )
        model = LitellmModel(model_name=model_name)
        system_template = r"""You are a bounded software-engineering worker operating through a shell.
Your response must contain exactly ONE bash command block in this format:
```mswea_bash_command
your_command_here
```
Work iteratively: inspect, edit, test, and verify. Never publish or change remote Git state.
When complete issue exactly:
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```"""
        instance_template = r"""{{ task }}
You are in {{ cwd }}. Work only inside the bounded repository and obey the task contract."""
        agent = DefaultAgent(
            model,
            env_obj,
            system_template=system_template,
            instance_template=instance_template,
            cost_limit=consumed_budget,
            step_limit=30,
            wall_time_limit_seconds=900,
        )
        task = f"""You are a bounded coding worker inside ForgeBoss.
Objective: {packet.get('objective','')}
IMMUTABLE RULES:
- Modify ONLY: {json.dumps(packet.get('allowed_files',[]))}
- Relevant context: {json.dumps(packet.get('context_files',[]))}
- Do not modify .github, credentials, generated files, or anything outside allowed_files.
- Do not push, publish, merge, deploy, alter remotes, or access network.
- Do not weaken tests.
- Use the repository already mounted at /workspace.
Required acceptance intent:
{json.dumps(packet.get('acceptance_criteria',[]))}"""
        agent.run(task)
        result["cost_usd"] = _observed_cost(getattr(agent, "cost", None))
        result["calls"] = int(getattr(agent, "n_calls", 0) or 0)
        post = subprocess.run(
            [
                sys.executable,
                str(guard),
                "postflight",
                "--lease",
                lease,
                "--token",
                lease_token,
                "--packet",
                str(packet_path),
                "--workspace",
                workspace,
                "--executor",
                "mini-swe",
            ],
            capture_output=True,
            text=True,
        )
        if post.returncode:
            result["error"] = "ForgeBoss postflight denied worker result: " + (post.stdout or post.stderr)[-1200:]
            return 13
        result["completed"] = True
        return 0
    except Exception as ex:
        try:
            if "agent" in locals():
                result["cost_usd"] = _observed_cost(getattr(agent, "cost", None))
                result["calls"] = int(getattr(agent, "n_calls", 0) or 0)
        except Exception:
            pass
        result["error"] = f"{type(ex).__name__}: {ex}"
        print(result["error"], file=sys.stderr)
        return 10
    finally:
        try:
            if env_obj is not None:
                env_obj.cleanup()
        except Exception:
            pass
        print("FORGEBOSS_RESULT_JSON=" + json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    raise SystemExit(main())
