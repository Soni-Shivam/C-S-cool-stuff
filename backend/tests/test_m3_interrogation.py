import pytest

from drishti.ledger import Ledger
from drishti.sandbox.interrogation import (
    AttemptResult, InstrumentationSelection, InterrogationController,
    InterrogationLimits, StructuralHypothesis,
)
from drishti.sandbox.stimuli import StimulusRunner


TS = "2026-08-11T00:00:00Z"


def hypothesis(identifier="h1", depth=0):
    return StructuralHypothesis(id=identifier, statement="Cipher output may feed a local loader", evidence_refs=["n1"], depth=depth)


def test_allowlisted_closed_loop_records_crash_repair_stimulus_and_observation():
    ledger = Ledger()
    states = iter([
        AttemptResult(state="crashed", crash_summary="redacted SIGSEGV"),
        AttemptResult(state="observed", observations=["Cipher.doFinal called with redacted dummy buffer"]),
    ])
    selector = lambda h, attempt, prior: InstrumentationSelection(
        hook_ids=["hook.cipher_do_final"], stimulus_ids=["stimulus.ui_monkey"],
        rationale=f"bounded attempt {attempt}",
    )
    controller = InterrogationController(selector=selector, executor=lambda *_: next(states), ledger=ledger, timestamp=TS)
    summary = controller.run([hypothesis()])
    assert summary.attempts == 2 and summary.observed == 1
    types = [node.type for node in ledger.nodes]
    assert "m3_retry" in types and "m3_stimulus" in types and "dynamic_obs" in types
    assert any(node.content.startswith("[OBSERVED]") for node in ledger.nodes)


def test_arbitrary_hook_or_stimulus_is_rejected_before_executor():
    called = False
    def executor(*_):
        nonlocal called
        called = True
        return AttemptResult(state="no_observation")
    selector = lambda *_: InstrumentationSelection(hook_ids=["shell.rm_everything"], rationale="bad")
    controller = InterrogationController(selector=selector, executor=executor, ledger=Ledger(), timestamp=TS)
    with pytest.raises(ValueError, match="unapproved"):
        controller.run([hypothesis()])
    assert called is False


def test_limits_disallow_more_than_three_retries_or_30_minutes():
    with pytest.raises(ValueError): InterrogationLimits(max_attempts_per_hypothesis=4)
    with pytest.raises(ValueError): InterrogationLimits(max_total_runtime_s=1801)


def test_stimulus_runner_uses_fixed_argv_and_rejects_unknown_ids(tmp_path):
    calls = []
    def command(args, **kwargs):
        calls.append((args, kwargs))
        return __import__("subprocess").CompletedProcess(args, 0, "", "")
    runner = StimulusRunner(command=command, fixture_dir=tmp_path)
    assert runner.apply(["stimulus.synthetic_sms", "stimulus.fake_c2_template"]) == [
        "stimulus.synthetic_sms", "stimulus.fake_c2_template"]
    assert all(isinstance(args, list) and kwargs["check"] is False for args, kwargs in calls)
    assert all("shell" not in kwargs for _, kwargs in calls)
    with pytest.raises(ValueError, match="unapproved"):
        runner.apply(["stimulus.arbitrary_shell"])


def test_frida_hooks_call_bound_overloads_instead_of_recursive_this_calls():
    hooks = (__import__("pathlib").Path(__file__).parents[1] / "scripts" / "frida_hooks.js").read_text()
    forbidden = ("return this.sendTextMessage(", "return this.getMessageBody(", "return this.doFinal(",
                 "return this.openConnection(", "return this.setPrimaryClip(", "return this.$init(")
    assert not any(pattern in hooks for pattern in forbidden)
    assert "original.call(this" in hooks and "source_hook" in hooks
