"""Live-browser verification for the new frontend evidence-download
affordance (Gap Audit Milestone JJ follow-up): real case-lead login, real
new case, real evidence upload via the actual running UI, wait for the
autonomous pipeline to reach a downloadable state, then click the new
Download button in EvidenceDetailDrawer and confirm a real file with the
correct bytes is saved by the browser.

Run: ~/venv/bin/python3 poc/evidence_download_ui/run_poc.py
Requires the dev stack up, including a freshly rebuilt docker-nginx-1 image
(this PoC's own commit rebuilds it) so the new frontend code is served.
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

BACKEND = "https://kronos.local"
SCREENSHOT_DIR = Path(__file__).resolve().parent / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)
SAMPLE_FILE = Path(__file__).resolve().parents[2] / "tests/fixtures/samples/nginx.log"

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"{'PASS' if ok else 'FAIL'}: {label}")


def main() -> None:
    assert SAMPLE_FILE.exists(), f"missing sample: {SAMPLE_FILE}"
    real_sha256 = hashlib.sha256(SAMPLE_FILE.read_bytes()).hexdigest()

    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--ignore-certificate-errors"])
        context = browser.new_context(ignore_https_errors=True, accept_downloads=True)
        page = context.new_page()

        print("=== LOGIN as case-lead ===")
        page.goto(f"{BACKEND}/cases", timeout=20000)
        page.wait_for_selector("text=Sign in with SSO", timeout=15000)
        page.click("text=Sign in with SSO")
        page.wait_for_selector("#username", timeout=15000)
        page.fill("#username", "case-lead")
        page.fill("#password", "DevCaseLead#2026")
        page.click("#kc-login")
        page.wait_for_url(f"{BACKEND}/cases**", timeout=20000)
        page.wait_for_selector("text=New Case", timeout=15000)
        check("landed on /cases after real Keycloak login", "/cases" in page.url)

        print("=== CREATE a new case ===")
        page.click("text=New Case")
        page.wait_for_selector("input[placeholder='Investigation title']", timeout=5000)
        page.fill("input[placeholder='Investigation title']", "Evidence download UI check")
        page.fill("input[placeholder*='CASE-']", "CASE-2026-UXDL1")
        with page.expect_response(
            lambda r: "/api/cases" in r.url and r.request.method == "POST", timeout=15000
        ) as resp_info:
            page.click("button:has-text('Create')")
        resp = resp_info.value
        check("real POST /api/cases returns 201", resp.status == 201)
        case_id = resp.json()["id"]

        page.goto(f"{BACKEND}/cases/{case_id}", timeout=20000)
        page.wait_for_selector("text=Upload Evidence", timeout=15000)

        print("=== UPLOAD real evidence ===")
        page.click("text=Upload Evidence")
        page.wait_for_selector("input[type=file]", timeout=5000)
        page.locator("input[type=file]").set_input_files(str(SAMPLE_FILE))
        submit = page.get_by_role("button", name="Upload", exact=True)
        submit.wait_for(state="visible", timeout=5000)
        check("real Upload submit button became enabled after file selection", submit.is_enabled())
        with page.expect_response(
            lambda r: "/api/evidence/upload/finalize/" in r.url and r.request.method == "POST",
            timeout=20000,
        ) as finalize_resp_info:
            submit.click()
        finalize_resp = finalize_resp_info.value
        check(
            "real POST /api/evidence/upload/finalize/{id} returns 202 Accepted "
            "(async pipeline dispatch, CLAUDE.md SS E.1)",
            finalize_resp.status == 202,
        )

        print("=== Wait for the autonomous pipeline to reach a downloadable state ===")
        # Real states past HASHING (RECEIVED/PARSING/COMPLETE) are all
        # downloadable per the backend's own promotion point -- poll the
        # real evidence row rather than assuming a fixed timeout.
        row_selector = "table tbody tr"
        page.wait_for_selector(row_selector, timeout=15000)
        downloadable = False
        for _ in range(30):
            page.reload()
            page.wait_for_selector(row_selector, timeout=15000)
            row_text = page.locator(row_selector).first.inner_text()
            if any(s in row_text for s in ("Received", "Parsing", "Complete", "Ingesting")):
                downloadable = True
                break
            page.wait_for_timeout(1000)
        check("evidence row reached a real, post-hashing state", downloadable)
        page.screenshot(path=str(SCREENSHOT_DIR / "1_evidence_row.png"))

        print("=== Open the drawer and click Download ===")
        page.locator("text=Details").first.click()
        page.wait_for_selector("text=Evidence Details", timeout=5000)
        download_button = page.locator("button", has_text="Download")
        check("Download button is visible in the real drawer", download_button.count() > 0)
        page.screenshot(path=str(SCREENSHOT_DIR / "2_drawer_with_download_button.png"))

        with page.expect_download(timeout=15000) as download_info:
            download_button.first.click()
        download = download_info.value
        saved_path = Path(tempfile.mkdtemp()) / download.suggested_filename
        download.save_as(str(saved_path))
        check(
            "browser actually saved a real downloaded file",
            saved_path.exists() and saved_path.stat().st_size > 0,
        )
        check(
            "suggested filename matches the real uploaded filename",
            download.suggested_filename == "nginx.log",
        )

        downloaded_sha256 = hashlib.sha256(saved_path.read_bytes()).hexdigest()
        check(
            "downloaded file's SHA-256 matches the real uploaded sample byte-for-byte",
            downloaded_sha256 == real_sha256,
        )

        browser.close()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
