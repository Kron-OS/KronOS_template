# PoC: `Content-Disposition` filename crash from unsanitized control characters (Gap Audit Milestone DD)

## Background

Self-found during a direct security review of X1's evidence-download
route (`src/external/routes/cases.py::download_evidence`) and W3's
audit-export route (`src/external/routes/audit.py`) — both build a
`Content-Disposition` header from a string that, before this fix, was
only ever escaped for double quotes
(`evidence.metadata.original_filename.replace('"', "")`).

`evidence.metadata.original_filename` comes from
`UploadRequestIn.filename: str = Field(min_length=1, max_length=1024)`
(`src/external/routes/evidence.py`) — bounded only by length, never
content, which is intentional and correct for a DFIR platform (evidence
from a compromised host may legitimately have adversarial/malformed
filenames; validation must not reject the evidence itself). But that same
unrestricted string reaches a raw f-string HTTP header with no CR/LF
stripping.

## Real, live impact (not header injection — a real availability bug)

Confirmed directly against a real running `uvicorn` server (not assumed,
not just inspected as a Python object — see `repro_server.py`/
`output.txt`): a filename containing a raw `\r\n` reaches h11 (the
HTTP/1.1 implementation uvicorn uses), which validates header values
against its own strict field-value grammar and refuses to serialize the
response at all — `h11._util.LocalProtocolError: Illegal header value`.
The client sees "Empty reply from server" / a hung connection; the server
logs an unhandled exception. **This is not exploitable as header
injection or response splitting** — h11 defends against that at the
protocol level, confirmed the same way. It is a real, live **availability**
bug: any authenticated user with ordinary evidence-upload permission
(not an admin action) can permanently break the download route for that
evidence item, for every user in the org, with a single crafted filename.

Note: Starlette's own `TestClient` (httpx-based, in-process ASGI
transport) does **not** reproduce this — it never serializes to real
HTTP/1.1 bytes, so it never exercises h11's validation. A unit test using
only `TestClient` would report the header as delivered whether or not it
contained real CR/LF (confirmed: `tests/unit/test_cases_routes.py`'s own
new regression test fails on its own explicit `"\r" not in header`
assertion against unfixed code, not on a framework-level crash). This
`poc/` directory's real-uvicorn reproduction is what actually demonstrates
production impact, per CLAUDE.md §F ("real observed output... not
assumed") — the unit test alone would not have caught this.

## Fix

`src/external/routes/_http_helpers.py::sanitize_content_disposition_filename()`
— strips all C0 control characters (`0x00`-`0x1F`) and DEL (`0x7F`) plus
the double quote; real Unicode filenames (CJK, Cyrillic, emoji, etc.) are
left untouched. Used by both `cases.py::download_evidence` and
`audit.py`'s export route (the latter's filename includes
`tenant.org_alias`, a lower-severity instance of the same class — an org
admin could only ever break their own org's export, not any other
tenant's — fixed for consistency and defense-in-depth).

## Verified (real, not assumed)

`output.txt` — three real, captured parts:
1. Pre-fix behavior against a real `uvicorn` server: real client-side
   "Empty reply from server", real server-side
   `h11._util.LocalProtocolError`.
2. Post-fix behavior against a real `uvicorn` server: real `200 OK`, real
   correctly-sanitized `Content-Disposition` header, zero server errors.
3. Full backend test suite: 1975 → 1976 passed (+1, the new regression
   test), 2 skipped both times. `ruff`/`black`/`mypy` clean. The new test
   was independently confirmed to genuinely fail against the pre-fix code
   (not just written to trivially pass) by temporarily reverting the fix
   and re-running it in isolation.

## How to run

```
# Part 1 (pre-fix): REPRO_USE_FIX unset or 0
uvicorn --app-dir poc/evidence_download_filename_sanitization repro_server:app --port 18127
curl -v http://localhost:18127/download   # hangs / empty reply; check server stderr

# Part 2 (post-fix):
REPRO_USE_FIX=1 uvicorn --app-dir poc/evidence_download_filename_sanitization repro_server:app --port 18128
curl -D - -o /dev/null http://localhost:18128/download   # clean 200
```
