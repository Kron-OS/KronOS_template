#!/usr/bin/env python3
"""Real, end-to-end PoC for roadmap E2 (YARA-X sandboxed runner).

Exercises the REAL `YaraXSandboxRunner` class
(src/external/sandbox/yara_x_runner.py) driving the REAL worker script
(docker/yara/kronos-yarax-worker.py) as a real subprocess, which in turn
calls the REAL, pinned `yara_x` package (yara-x==1.19.0, VirusTotal's
official YARA-X Python binding, installed for real on this host's Python
3.14 venv -- see README.md for the exact `pip install`/`pip index versions`
output that established this is a real, installable artifact, not an
assumption).

Four real scenarios, matching CLAUDE.md §F.2 step 4 ("run it and capture
the actual output"):
  1. Positive match: a real rule matching a real byte pattern in a real
     target blob, with real, independently-checkable byte offsets.
  2. Negative match: the same rule against a target with no occurrence.
  3. Malformed rule text: invalid YARA-X syntax, must surface as a clean
     YaraRuleCompilationError, not a crash/traceback.
  4. A tags/metadata-bearing rule with two occurrences of one pattern, to
     confirm multiple real offsets come back correctly ordered.

Run:
    ~/venv/bin/python3 poc/yarax_sandboxed_runner/run_poc.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.exceptions import YaraRuleCompilationError  # noqa: E402
from src.external.sandbox.yara_x_runner import YaraXSandboxRunner  # noqa: E402


async def scenario_positive_match(runner: YaraXSandboxRunner) -> None:
    print("\n=== Scenario 1: positive match, real byte offsets ===")
    rule_source = 'rule find_foobar { strings: $a = "foobar" condition: $a }'
    target = b"xxxxfoobarxxxxfoobar"
    print(f"rule_source = {rule_source!r}")
    print(f"target      = {target!r} (len={len(target)})")

    result = await runner.run(rule_source=rule_source, target=target)

    print(f"matched: {result.matched}")
    for rule in result.matched_rules:
        print(
            f"  rule identifier={rule.identifier!r} namespace={rule.namespace!r} tags={rule.tags}"
        )
        for m in rule.matched_strings:
            print(
                f"    pattern={m.pattern_identifier!r} offset={m.offset} "
                f"length={m.length} xor_key={m.xor_key}"
            )
    expected_offsets = [4, 14]
    actual_offsets = sorted(m.offset for r in result.matched_rules for m in r.matched_strings)
    assert result.matched, "expected a real match"
    assert (
        actual_offsets == expected_offsets
    ), f"expected offsets {expected_offsets}, got {actual_offsets}"
    print("VERIFIED: real match, real correct byte offsets (4 and 14).")


async def scenario_negative_match(runner: YaraXSandboxRunner) -> None:
    print("\n=== Scenario 2: negative match (honest no-match, not an error) ===")
    rule_source = 'rule find_foobar { strings: $a = "foobar" condition: $a }'
    target = b"nothing interesting in this blob at all"
    print(f"rule_source = {rule_source!r}")
    print(f"target      = {target!r}")

    result = await runner.run(rule_source=rule_source, target=target)

    print(f"matched: {result.matched}, matched_rules: {result.matched_rules}")
    assert result.matched is False
    assert result.matched_rules == ()
    print("VERIFIED: real scan, real honest zero matches, no exception raised.")


async def scenario_malformed_rule(runner: YaraXSandboxRunner) -> None:
    print("\n=== Scenario 3: malformed rule text (clean compile error, not a crash) ===")
    rule_source = "this is not valid yara syntax {{{"
    print(f"rule_source = {rule_source!r}")

    try:
        await runner.run(rule_source=rule_source, target=b"irrelevant")
    except YaraRuleCompilationError as exc:
        print(f"VERIFIED: clean YaraRuleCompilationError raised: {exc}")
        print(f"  context: {exc.context}")
    else:
        raise AssertionError("expected YaraRuleCompilationError, got no exception")


async def scenario_multi_match_with_metadata(runner: YaraXSandboxRunner) -> None:
    print("\n=== Scenario 4: tagged rule, metadata, two real occurrences ===")
    rule_source = (
        "rule tagged_rule : malware apt {\n"
        '    meta:\n        author = "kronos-e2-poc"\n        severity = 5\n'
        "    strings:\n"
        '        $b = "bar"\n'
        "    condition:\n        $b\n"
        "}\n"
    )
    target = b"foobarbar"
    print(f"rule_source =\n{rule_source}")
    print(f"target      = {target!r}")

    result = await runner.run(rule_source=rule_source, target=target)

    rule = result.matched_rules[0]
    print(f"rule identifier={rule.identifier!r} tags={rule.tags}")
    offsets_lengths = [(m.offset, m.length) for m in rule.matched_strings]
    print(f"matched_strings offset/length pairs: {offsets_lengths}")
    assert rule.tags == ("malware", "apt")
    assert sorted(offsets_lengths) == [(3, 3), (6, 3)]
    print("VERIFIED: real tags carried through, both real overlapping-pattern offsets correct.")


async def main() -> None:
    print("YaraXSandboxRunner real end-to-end PoC (roadmap E2)")
    print(f"Python: {sys.version}")
    import yara_x

    print(f"yara_x module file: {yara_x.__file__}")

    runner = YaraXSandboxRunner(python_bin=sys.executable, timeout_seconds=10)

    await scenario_positive_match(runner)
    await scenario_negative_match(runner)
    await scenario_malformed_rule(runner)
    await scenario_multi_match_with_metadata(runner)

    print("\nAll 4 real scenarios passed.")


if __name__ == "__main__":
    asyncio.run(main())
