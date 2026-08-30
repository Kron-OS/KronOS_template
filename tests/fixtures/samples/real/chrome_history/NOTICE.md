# Provenance

`History` is the exact same real Chrome-family SQLite history database
already committed at `tests/fixtures/samples/real/kape/kape_triage.zip`'s
own `C/Users/jdoe/AppData/Local/Google/Chrome/User Data/Default/History`
member (see that directory's own `NOTICE.md` for the file's original
provenance — sourced from the [Plaso](https://github.com/log2timeline/plaso)
project's `test_data/`, redistributed unmodified under Apache License 2.0).

Extracted here, standalone and with its real original (extension-less)
filename preserved, so `ChromeHistoryParser` can be exercised directly by
a real top-level evidence upload — previously this file was only ever
uploaded as a member *inside* the zip container, never as its own evidence
item (Gap Audit Milestone XXX's coverage-gap finding #2: FAST-tier parsers
were the platform's least end-to-end-verified tier by comparison to the
HEAVY-tier push of Milestones UUU-WWW).

Used by `frontend/e2e/evidence-upload-fast-parsers.spec.ts`.
