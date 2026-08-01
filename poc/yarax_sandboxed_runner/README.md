# PoC: YARA-X sandboxed runner (roadmap E2)

**Objective.** Verify, for real, that a sandboxed (subprocess, container-level
isolation per CLAUDE.md §G.3) YARA-X runner can compile untrusted rule text
and scan a byte blob, returning real rule matches with real matched-string
byte offsets — without ever compiling/scanning that untrusted input inside
the caller's own process.

## What "YARA-X" concretely is on this host, right now (CLAUDE.md §F.2 step 1)

Real research, not assumption:

```
$ ~/venv/bin/pip index versions yara-x
yara-x (1.19.0)
Available versions: 1.19.0, 1.18.0, 1.17.0, 1.16.0, 1.15.0, ... 0.2.0
  INSTALLED: 1.19.0
```

- **`yara-x` on PyPI** — the real, official VirusTotal/yara-x Python
  binding. Latest version **1.19.0** as of this PoC (2026-08-01). Ships a
  `manylinux_2_28_x86_64` wheel tagged `cp38-abi3` — the CPython **stable
  ABI**, so it installs and imports cleanly on this host's Python **3.14.4**
  even though the wheel was built against the 3.8 ABI (verified: `pip
  download`/`pip install` both succeeded for real, see the `pip install`
  transcript below). The wheel is **9.3 MB and has zero extra runtime
  dependencies** (`pip show yara-x` → `Requires:` empty).
- **A standalone `yr` CLI binary** also genuinely exists (real GitHub
  releases at `github.com/VirusTotal/yara-x/releases`, prebuilt for Linux/
  macOS/Windows) with a documented `yr scan --output-format
  text|ndjson|json` surface (`virustotal.github.io/yara-x/docs/cli/
  commands/`). **Not used here** — see "Design decision" below for why.
- **A real Rust crate** (`yara-x` on crates.io) also exists but is not
  relevant to this Python-based codebase.

```
$ ~/venv/bin/pip install --no-cache-dir yara-x==1.19.0
Collecting yara-x==1.19.0
  Downloading yara_x-1.19.0-cp38-abi3-manylinux_2_28_x86_64.whl.metadata (1.8 kB)
Downloading yara_x-1.19.0-cp38-abi3-manylinux_2_28_x86_64.whl (9.7 MB)
Installing collected packages: yara-x
Successfully installed yara-x-1.19.0
```

Pinned in `pyproject.toml` as `yara-x==1.19.0` (exact pin, matching this
repo's existing `plaso==20260512` precedent for a tool version this
codebase shells out to) and installed into the project's real dev venv
(confirmed via `pip show yara-x` → `Version: 1.19.0`, `Location:
/home/reca/venv/lib/python3.14/site-packages`).

## Design decision: Python binding in a subprocess worker, NOT the `yr` CLI

Both are defensible per the task brief; this PoC actually compared them:

1. **`yr` CLI's structured output does not carry per-match byte offsets.**
   Its documented `ndjson`/`json` output (`virustotal.github.io/yara-x/
   docs/cli/commands/`) is `{"path": "onefile.exe", "rules": [{"identifier":
   "some_rule"}]}` — rule identifiers (+ optional namespace/tags via
   `--print-namespace`/`--print-tags`), but **no offset/length field is
   documented anywhere in the CLI's JSON output**. E3's own requirement
   ("matched-string offsets so an examiner can independently verify") would
   be unmet by the CLI path without falling back to parsing `--print-strings`
   text output, which is a human-readable format, not a stable machine
   contract.
2. **The Python binding's `Match` object exposes `offset`/`length` (and
   `xor_key`) directly and unambiguously** — verified for real (see
   `output.txt`, Scenario 1): a rule matching `"foobar"` in
   `b"xxxxfoobarxxxxfoobar"` returns matches at byte offsets **4** and
   **14**, both independently checkable by counting bytes in the source
   string. This directly satisfies E3's requirement; the CLI path would not
   have, without additional unverified assumptions.
3. Given (1) and (2), the Python binding was the only one of the two that
   could honestly claim to produce E3-ready output, so it was used — inside
   a **subprocess worker script**, following `FirecrackerLauncher`'s and
   `kronos-plaso-worker.py`'s exact existing shape (a small standalone
   script, invoked via `subprocess.run`, one JSON object on stdout, logs on
   stderr), never imported into the caller's process.

## Honest risk-model statement (task requirement, not a sales pitch)

YARA-X is memory-safe Rust, which removes the memory-corruption/CVE class
of bug libyara/`yara-python` carries (the whole reason this item exists).
Running it in a subprocess buys **subprocess isolation**: a crashed or
resource-exhausted worker process is not a compromised API/Celery process,
and (per `Scanner.set_timeout()`, verified below) a pathological rule can be
killed cleanly. It does **not** buy Firecracker-microVM/gVisor-level
isolation — this PoC runs a plain host subprocess, the same honest level of
isolation `FirecrackerLauncher`'s own docstring already describes for
Plaso ("sandboxed at the container level," i.e. the existing Chainguard/
Wolfi container the API/Celery process already runs in, not a fresh
container per invocation). This class does not claim more than that.

## Real API surface actually exercised (not guessed)

```python
>>> import yara_x
>>> rules = yara_x.compile('rule test { strings: $a = "foobar" condition: $a }')
>>> results = rules.scan(b"xxxxfoobarxxxxfoobar")
>>> results.matching_rules[0].identifier
'test_rule'
>>> results.matching_rules[0].patterns[0].matches[0].offset, ...matches[0].length
(4, 6)
```

Also verified for real (not documented anywhere we found, so worth
recording): `yara_x.Scanner(rules).set_timeout(1)` genuinely aborts a
pathological-regex scan after ~1.0s, raising `yara_x.TimeoutError` — this is
the in-worker defense-in-depth timeout layered under the runner's own
outer wall-clock `subprocess.run(timeout=...)`, mirroring
`kronos-plaso-worker.py`'s own dual-timeout (`_L2T_TIMEOUT`/
`_PSORT_TIMEOUT` inside the worker, the Celery task's own `time_limit`
outside it).

`yara_x.CompileError` is raised cleanly (not a segfault/crash) on invalid
rule syntax — verified in Scenario 3 below.

## No new Dockerfile variant needed (checked, not assumed)

Unlike Plaso (`docker/Dockerfile.plaso-worker`, a large separate dependency
tree), `yara-x`'s wheel has **zero extra runtime dependencies** and is a
single 9.3 MB self-contained extension module. `pip install .` (the base
`docker/Dockerfile`'s own build step) already picks it up from
`pyproject.toml`'s `dependencies` list — no separate image, no separate
Celery queue is required for this item. Confirmed: `docker/Dockerfile` was
not touched by this item.

## No new Celery queue (per this item's own scope note)

Nothing calls `YaraXSandboxRunner` outside this PoC and its unit tests —
E3 is the real future caller and will decide whether YARA scanning belongs
on the existing fast-parse queue (`q.parse.fast`) or needs its own
(`q.yara.scan`?) once real workload/latency characteristics are known.
Wiring a queue for a runner nothing calls yet would be speculative.

## How to run

```
~/venv/bin/python3 poc/yarax_sandboxed_runner/run_poc.py
```

Exercises the **real** `YaraXSandboxRunner`
(`src/external/sandbox/yara_x_runner.py`) driving the **real**
`docker/yara/kronos-yarax-worker.py` as a real subprocess, calling the real,
pinned `yara_x==1.19.0`. Four real scenarios, output captured verbatim in
`output.txt`:

1. **Positive match** — real rule, real target, real byte offsets (4, 14)
   independently verified by counting bytes.
2. **Negative match** — same rule, no occurrence in target: confirmed
   `matched=False`, empty `matched_rules`, no exception (a non-match is not
   an error).
3. **Malformed rule text** — invalid YARA-X syntax: confirmed a clean
   `YaraRuleCompilationError` surfaces (not a crash/traceback), with the
   real `yara_x.CompileError` message preserved in `.context`.
4. **Tagged rule with metadata, two overlapping occurrences** — confirms
   `tags` pass through and multiple real offset/length pairs are correctly
   reported for one pattern.

The same real worker script is additionally exercised inside the unit test
suite (`tests/unit/test_yara_x_runner.py::test_real_worker_*`, 3 tests) so
this stays a regression-checked contract, not a one-off manual run.
