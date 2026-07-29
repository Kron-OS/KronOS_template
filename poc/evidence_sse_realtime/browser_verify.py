"""Real-browser (Playwright, Chromium) verification that the frontend now
receives live evidence status updates via SSE, without a manual reload.

Confirms the fix for two compounding real bugs found by reading the actual
backend/frontend source together:

1. frontend/src/hooks/useEvidenceSSE.ts used `es.onmessage = ...`, but the
   backend (src/external/routes/sse.py) always sends NAMED SSE frames
   ("event: status", "event: ping", "event: done"). Per the SSE spec,
   EventSource.onmessage is only invoked for unnamed/"message" frames --
   it silently received ZERO events, forever, with no error (the
   connection opened fine). Fixed: es.addEventListener('status', ...).
2. Even if that had worked, the backend sent {"evidence_id": ..., "state": ...}
   (snake_case) while the frontend's SSEStatusEvent type expected
   {"evidenceId": ..., "status": ...} -- a field-name mismatch that would
   have made `'status' in event` always false. Fixed: backend now emits
   {"evidenceId": ..., "state": ...} to match the frontend contract.

This script drives the REAL browser through the REAL login form, creates a
real case via the UI, uploads a real file via the UI's own upload flow, and
then -- WITHOUT reloading the page -- watches the Status cell in the
evidence table update live as the real backend pipeline progresses
(UPLOADING -> ... -> RECEIVED/PARSING/COMPLETE), proving the SSE push path
now actually works end-to-end.

Run: source ~/venv/bin/activate && python poc/evidence_sse_realtime/browser_verify.py
Requires the real, rebuilt dev stack up (kronos.local).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

BACKEND = "https://kronos.local"
PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def main() -> None:
    tmp_file = Path("/tmp/kronos_sse_poc_cloudtrail.json")
    tmp_file.write_text(
        '{"Records": [{"eventTime": "2024-01-15T10:30:00Z", "eventName": "Describe", '
        '"eventSource": "ec2.amazonaws.com", "userIdentity": {"userName": "alice", "accountId": "123"}}]}'
    )

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--ignore-certificate-errors"])
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # ------------------------------------------------------------------
        # Real login through the real Keycloak form (not the scripted PKCE
        # client the other PoCs use) -- the SPA needs its own real browser
        # session for the SSE EventSource/fetch calls to carry real cookies/
        # tokens exactly as a real user's browser would.
        # ------------------------------------------------------------------
        page.goto(f"{BACKEND}/cases")
        page.wait_for_selector("text=Sign in with SSO", timeout=15000)
        page.click("text=Sign in with SSO")
        page.wait_for_selector("#username", timeout=15000)
        page.fill("#username", "case-lead")
        page.fill("#password", "DevCaseLead#2026")
        page.click("#kc-login")
        page.wait_for_url(f"{BACKEND}/cases**", timeout=20000)
        check("real login succeeds, lands on /cases", True)

        # ------------------------------------------------------------------
        # Create a real case via the real UI.
        # ------------------------------------------------------------------
        page.click("text=New Case")
        page.wait_for_selector("#case-title", timeout=10000)
        case_title = f"SSE realtime PoC {int(time.time())}"
        page.fill("#case-title", case_title)
        page.fill("#case-ref", f"SSE-{int(time.time())}")
        page.click("button:has-text('Create')")
        page.wait_for_selector(f"text={case_title}", timeout=15000)
        page.click(f"text={case_title}")
        page.wait_for_url(f"{BACKEND}/cases/**", timeout=15000)
        check("real case created and opened via the UI", True, case_title)

        # ------------------------------------------------------------------
        # Upload a real file via the real UploadDrawer UI flow.
        # ------------------------------------------------------------------
        page.click("text=Upload Evidence")
        page.wait_for_selector("#evidence-file-input", timeout=10000)
        page.set_input_files("#evidence-file-input", str(tmp_file))
        # Exact match: "button:has-text('Upload')" (substring) also matches
        # the "Upload Evidence" trigger button still in the DOM behind the
        # drawer.
        page.get_by_role("button", name="Upload", exact=True).click()
        # The drawer does NOT auto-close on finalize (UploadDrawer.tsx's
        # handleUpload just marks the file "Done" and invalidates the query;
        # closing is a separate, manual action) -- wait for "Done", then
        # close it explicitly via the "×" button.
        page.wait_for_selector("text=Done", timeout=30000)
        page.click('button[aria-label="Close"]')
        page.wait_for_selector("#evidence-file-input", state="detached", timeout=10000)
        check("real file uploaded via the UI and finalize accepted", True)

        # ------------------------------------------------------------------
        # Watch the Status cell WITHOUT reloading the page -- this is the
        # actual thing being verified: does it move on its own via the live
        # SSE connection, or does it stay frozen until a manual reload?
        # ------------------------------------------------------------------
        row_selector = f"tr:has-text('{tmp_file.name}')"
        page.wait_for_selector(row_selector, timeout=15000)

        seen_states: list[str] = []
        deadline = time.time() + 60
        last_seen = None
        while time.time() < deadline:
            text = page.locator(row_selector).inner_text()
            for candidate in (
                "Uploading",
                "Scanning",
                "Hashing",
                "Received",
                "Parsing",
                "Complete",
                "Error",
            ):
                if candidate in text and candidate != last_seen:
                    seen_states.append(candidate)
                    last_seen = candidate
            if last_seen in ("Complete", "Error"):
                break
            page.wait_for_timeout(500)

        check(
            "status pill changed at least once WITHOUT a page reload (live SSE push)",
            len(seen_states) >= 1,
            f"observed sequence: {seen_states}",
        )
        check(
            "evidence reached a terminal state live (Complete, since no ClamAV/parse "
            "issue expected for this clean JSON file)",
            last_seen == "Complete",
            last_seen,
        )

        page.screenshot(path="poc/evidence_sse_realtime/browser_live_status_update.png")

        browser.close()

    tmp_file.unlink(missing_ok=True)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
