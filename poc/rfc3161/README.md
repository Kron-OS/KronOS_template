# PoC: RFC3161TimestampService against a real RFC 3161 TSA responder

## Versions (pinned, read from this repo -- not assumed)
- `rfc3161ng`: pin is `rfc3161ng>=2.1.3` in `pyproject.toml`. Installed
  version confirmed at runtime via `importlib.metadata.version("rfc3161ng")`
  → `2.1.3` (in `~/venv`, the environment this repo's tests actually run in).
- Component under test: `src/application/timestamping.py` ->
  `RFC3161TimestampService` (`_build_timestamp_request`, `.timestamp()`,
  `.verify()`).

## Which real TSA, and why

The repo's own `docker/docker-compose.dev.yml` `tsa` service was read first,
per Section F.2 step 1-2, in full:

```yaml
tsa:
  # freetsa/freetsa has no public Docker image; use a lightweight stub for dev
  image: python:3.12-alpine
  command:
    - python
    - -c
    - |
      from http.server import HTTPServer, BaseHTTPRequestHandler
      class H(BaseHTTPRequestHandler):
          def do_POST(self):
              self.send_response(200)
              self.send_header('Content-Type','application/timestamp-reply')
              self.end_headers()
          def log_message(self, *a): pass
      HTTPServer(('0.0.0.0', 318), H).serve_forever()
  ports: ["318:318"]
```

This stub returns a bare HTTP 200 with the right `Content-Type` header and
**no response body at all**. It is not a real RFC 3161 responder: it can
never produce a decodable DER `TimeStampResp`, so `RFC3161TimestampService
.verify()` can't be exercised against it at all, and even `.timestamp()`
against it only proves an HTTP client can POST bytes somewhere -- it proves
nothing about whether the request/response actually round-trip as valid
RFC 3161 ASN.1. Using it here would be exactly the "confident-sounding,
unverified" anti-pattern Section F exists to stop.

Instead this PoC uses **`openssl ts`** as the real TSA, following the same
technique already present in this repo's own
`tests/unit/test_tsa_round_trip.py` (used there for the *different*
`kronos_attest.tsa.TSAVerifier` component). `openssl ts` is OpenSSL's own
RFC 3161 time-stamping authority/client tool (`man openssl-ts`) -- a real,
standards-following minimal TSA, not a reimplementation and not a stub. No
public TSA endpoint was used or fetched from the internet for this PoC; the
local openssl-backed responder is real enough (genuine ASN.1 encode/sign/
decode via a widely-deployed, standards-compliant tool) and avoids any risk
of following untrusted instructions from a fetched web page.

## What this actually does

`run_poc.py`:
1. Builds a throwaway CA + TSA certificate/key with real `openssl req`/
   `openssl x509` invocations (same commands as
   `tests/unit/test_tsa_round_trip.py`).
2. Starts a real local HTTP server on `127.0.0.1:20318`. Every `POST` it
   receives is answered by shelling out to a real `openssl ts -reply`
   invocation against the bytes it just received -- i.e. every response is a
   genuine ASN.1-signed `TimeStampResp`, produced fresh per request, not
   canned.
3. Drives the actual production code, unmodified except for the bug fix
   below:
   - `src.application.timestamping._build_timestamp_request(digest)` builds
     the real DER `TimeStampReq`.
   - `RFC3161TimestampService.timestamp(digest, hash_alg="sha256")` POSTs it
     over real HTTP and gets back the openssl-issued DER `TimeStampResp`.
   - `RFC3161TimestampService.verify(token, digest)` parses the real token
     via the real, pinned `rfc3161ng==2.1.3` and checks the embedded digest.
   - A **negative test**: `verify()` with the wrong digest, and
     `.timestamp()` against a TSA URL nothing listens on (port 1) --
     confirming both failure paths fail closed as designed, not silently.
   - Independently, `openssl ts -reply -in <token> -text` decodes the same
     token as a cross-check that isn't just re-parsing with the library
     under test.

Run:
```
~/venv/bin/python3 poc/rfc3161/run_poc.py
```
(rfc3161ng 2.1.3 and openssl must be available; both are already present in
`~/venv` / on this host.)

## Real finding: `.verify()` was completely broken and had never actually run

The **first** run of this PoC (before any fix) failed at `.verify()` with:

```
pyasn1.error.PyAsn1Error: Name tst_info not found
...
src.exceptions.TimestampingError: Failed to parse RFC 3161 TimeStampToken
```

Root-caused by inspecting the real `rfc3161ng` 2.1.3 objects interactively
(`rfc3161ng/types.py`, `rfc3161ng/api.py`), not by guessing:

1. **`tst["tst_info"]` is wrong -- `tst_info` is a property, not a dict
   key.** `rfc3161ng.types.TimeStampToken` (what
   `decode_timestamp_response(...).time_stamp_token` returns) only has
   dict-style keys `contentType`/`content` (it's a CMS `ContentInfo`
   wrapper). The decoded `TSTInfo` is exposed via the **`.tst_info`
   attribute** (a lazily-decoding `@property`; see `types.py:109-117`), not
   `tst["tst_info"]`. The old code always raised `PyAsn1Error` on this line,
   for every real token, every time.

2. **Field names are the ASN.1 camelCase names, not Python snake_case.**
   `TSTInfo`'s ASN.1 fields are named `genTime` and `messageImprint`
   (`types.py:163-181`), and `MessageImprint`'s field is `hashedMessage`
   (`types.py:19-23`) -- not `gen_time`/`message_imprint`/`hashed_message` as
   the old code assumed.

3. **pyasn1 objects have no `.native` accessor.** `rfc3161ng` is built on
   `pyasn1`, not `asn1crypto` -- the old code's `.native` calls were copied
   from the wrong ASN.1 library's API and would `AttributeError` even if the
   key names had been right. The real conversions are:
   `rfc3161ng.api.generalizedtime_to_utc_datetime(str(tstinfo["genTime"]))`
   for the timestamp, and `bytes(tstinfo["messageImprint"]["hashedMessage"])`
   for the digest.

**This means `RFC3161TimestampService.verify()` had never successfully
parsed any real TSA response, ever** -- every call to it, against any real
TSA (dev stub or production), would have raised `TimestampingError: Failed
to parse RFC 3161 TimeStampToken`, always. The existing unit tests in
`tests/unit/application/test_timestamping.py` never caught this because they
mocked `rfc3161ng` with a plain dict shaped like the *wrong* assumption
(`{"tst_info": {"gen_time": ...}}` with `.native` mocks) -- the tests
validated the bug's own shape, not the real library's shape. This is the
exact failure mode Section F names as worse than an admitted gap: confident,
green, unit-tested code that had never actually round-tripped against a real
TSA.

### Fix applied (`src/application/timestamping.py`, `verify()`)

```python
tst_info = tst.tst_info
gen_time = rfc3161ng.api.generalizedtime_to_utc_datetime(str(tst_info["genTime"]))
embedded_digest = bytes(tst_info["messageImprint"]["hashedMessage"])
```
replacing the old, always-failing:
```python
gen_time = tst["tst_info"]["gen_time"].native
embedded_digest = tst["tst_info"]["message_imprint"]["hashed_message"].native
```

`tests/unit/application/test_timestamping.py`'s two `rfc3161ng`-parsing tests
were also updated so their fakes mirror the real 2.1.3 API shape (attribute
`tst_info`, camelCase keys, no `.native`) -- confirmed against this PoC's real
openssl-issued token, so they would now actually catch a regression of this
bug instead of only checking their own wrong assumption.

## After the fix: full real round trip, captured in `output.txt`

```
RFC3161TimestampService.timestamp() returned 2269 bytes of real DER TimeStampResp from the real TSA.
...
--- openssl's own independent decode of the returned token ---
Status: Granted.
...
Message data:
    0000 - 66 5d 86 a9 25 af 9c 73-1f 33 de 73 8c 46 17 b8
    0010 - 48 2b fb 1f 90 2e 77 fa-c4 ec 64 0e 27 ad 0b 12
...
--- Step 2: verify() the real token against the real digest ---
RFC3161TimestampService.verify() succeeded. genTime = datetime.datetime(2026, 7, 21, 20, 44, 25)

--- Step 3: negative test -- verify() must REJECT wrong digest ---
verify() correctly raised TimestampingError: TSA token digest mismatch

--- Step 4: negative test -- .timestamp() against an unreachable TSA ---
.timestamp() correctly raised StorageError for unreachable TSA: TSA unreachable

PoC PASSED: real round trip (.timestamp() -> real TSA -> .verify())
confirmed correct, and both negative paths fail closed as designed.
```

The embedded message digest openssl reports (`66 5d 86 a9 ... 27 ad 0b 12`)
matches the sha256 digest the PoC computed and asked to be timestamped
(`665d86a9...27ad0b12`), and `RFC3161TimestampService.verify()` -- using the
real, pinned `rfc3161ng==2.1.3` -- extracts the same digest and the same
`genTime` (2026-07-21 20:44:25 UTC, matching openssl's own `Jul 21 20:44:25
2026 GMT`) independently. Both negative paths (wrong digest, unreachable
TSA) fail closed as the class's docstring promises, confirmed by actually
raising the exceptions rather than assuming it.

See `output.txt` for the complete, unedited console capture of the last real
run (`~/venv/bin/python3 poc/rfc3161/run_poc.py`).
