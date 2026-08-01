#!/usr/bin/env python3
"""KronOS YARA-X worker: compile rule source and scan a target file, emitting
one JSON result document to stdout.

Invoked by YaraXSandboxRunner (src/external/sandbox/yara_x_runner.py); the
launcher feeds rule-file/target-file paths + a per-scan timeout via CLI args,
and reads exactly one JSON object back from stdout -- same "small standalone
script, JSON in/out, everything else on stderr" shape as
docker/plaso/kronos-plaso-worker.py. Unlike the Plaso worker (which always
exits 0 and signals failure only through its own JSON `data_type`/stderr),
this worker's JSON payload carries an explicit `status` field so the launcher
can distinguish a rule-author error (bad YARA syntax: "compile_error") from a
real scan failure ("scan_error"/"timeout") from a genuine, possibly
zero-match, success ("ok") -- see src/exceptions.py's
YaraRuleCompilationError vs YaraScanError split for why that distinction
matters to callers.

Uses the real `yara_x` PyPI package (pinned yara-x==1.19.0 in
pyproject.toml) -- YARA-X's own official Python binding, a Rust extension
compiled to the CPython stable ABI (verified: installs cleanly on this
host's Python 3.14 via a manylinux abi3 wheel with zero extra runtime
dependencies, see poc/yarax_sandboxed_runner/README.md). Runs inside this
subprocess, never inside the caller's (API/Celery worker) process --
CLAUDE.md §G.3.

Usage:
    python kronos-yarax-worker.py \
        --rule-file /tmp/rule.yar \
        --target-file /tmp/target.bin \
        --timeout-seconds 30
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("kronos-yarax-worker")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KronOS YARA-X sandboxed scan worker")
    p.add_argument("--rule-file", required=True)
    p.add_argument("--target-file", required=True)
    p.add_argument("--timeout-seconds", type=int, default=30)
    return p.parse_args()


def _emit(result: dict) -> None:
    """Write the single JSON result document to stdout."""
    print(json.dumps(result, default=str), flush=True)


def _rule_match_to_dict(rule: object) -> dict:
    """Map one real `yara_x.Rule` match onto this worker's stable JSON contract."""
    matched_strings = []
    for pattern in rule.patterns:  # type: ignore[attr-defined]
        for match in pattern.matches:
            matched_strings.append(
                {
                    "pattern_identifier": pattern.identifier,
                    "offset": match.offset,
                    "length": match.length,
                    "xor_key": match.xor_key,
                }
            )
    return {
        "identifier": rule.identifier,  # type: ignore[attr-defined]
        "namespace": rule.namespace,  # type: ignore[attr-defined]
        "tags": list(rule.tags),  # type: ignore[attr-defined]
        "matched_strings": matched_strings,
    }


def main() -> None:
    args = _parse_args()
    logger.info("Starting YARA-X scan: rules=%s target=%s", args.rule_file, args.target_file)

    try:
        import yara_x
    except ImportError as exc:
        # This worker's own runtime is missing the real dependency -- an
        # infrastructure problem, not a rule-author problem, so this is a
        # scan_error, never compile_error.
        logger.error("yara_x is not importable in this worker's runtime: %s", exc)
        _emit(
            {
                "status": "scan_error",
                "error": f"yara_x not installed in worker runtime: {exc}",
                "matched_rules": [],
            }
        )
        sys.exit(0)

    with open(args.rule_file, encoding="utf-8") as fh:
        rule_source = fh.read()

    try:
        rules = yara_x.compile(rule_source)
    except yara_x.CompileError as exc:
        logger.warning("YARA-X rule compilation failed: %s", exc)
        _emit({"status": "compile_error", "error": str(exc), "matched_rules": []})
        sys.exit(0)

    with open(args.target_file, "rb") as fh:
        target_bytes = fh.read()

    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(args.timeout_seconds)

    try:
        results = scanner.scan(target_bytes)
    except yara_x.TimeoutError as exc:
        logger.error(
            "YARA-X scan exceeded its %ss in-worker timeout: %s", args.timeout_seconds, exc
        )
        _emit({"status": "timeout", "error": str(exc), "matched_rules": []})
        sys.exit(0)
    except yara_x.ScanError as exc:
        logger.error("YARA-X scan failed: %s", exc)
        _emit({"status": "scan_error", "error": str(exc), "matched_rules": []})
        sys.exit(0)

    matched_rules = [_rule_match_to_dict(rule) for rule in results.matching_rules]

    logger.info("YARA-X scan complete: %d rule(s) matched", len(matched_rules))
    _emit({"status": "ok", "error": None, "matched_rules": matched_rules})
    sys.exit(0)


if __name__ == "__main__":
    main()
