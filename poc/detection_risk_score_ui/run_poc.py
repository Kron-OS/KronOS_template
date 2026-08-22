"""Live-browser verification for the new frontend riskScore/riskFactors
UI (Gap Audit Milestone MM): real login, real Detections list, confirm
the new RiskScorePill renders on both the list row and the detail page,
and that the Risk Score Breakdown table shows real factor data -- not
just a unit-test mock.

Run: ~/venv/bin/python3 poc/detection_risk_score_ui/run_poc.py
Requires the dev stack up with a docker-nginx-1 rebuilt from the current
frontend source.
"""
from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BACKEND = "https://kronos.local"
SCREENSHOT_DIR = Path(__file__).resolve().parent / "screenshots"
SCREENSHOT_DIR.mkdir(exist_ok=True)

CHECKS: list[tuple[str, bool]] = []


def check(label: str, ok: bool) -> None:
    CHECKS.append((label, ok))
    print(f"{'PASS' if ok else 'FAIL'}: {label}")


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--ignore-certificate-errors"])
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.on("console", lambda msg: print(f"[console {msg.type}] {msg.text}"))
        page.on("pageerror", lambda exc: print(f"[pageerror] {exc}"))

        print("=== LOGIN as admin ===")
        page.goto(f"{BACKEND}/cases", timeout=20000)
        page.wait_for_selector("text=Sign in with SSO", timeout=15000)
        page.click("text=Sign in with SSO")
        page.wait_for_selector("#username", timeout=15000)
        page.fill("#username", "admin")
        page.fill("#password", "DevAdmin#2026")
        page.click("#kc-login")
        page.wait_for_url(f"{BACKEND}/cases**", timeout=20000)

        print("=== NAVIGATE: Detections list (client-side link, not a hard reload) ===")
        page.click("text=Detections")
        page.wait_for_url(f"{BACKEND}/detections**", timeout=15000)
        page.wait_for_timeout(2000)
        print(f"landed on: {page.url}")
        print("body text snapshot:\n" + page.locator("body").inner_text()[:1000])
        page.screenshot(path=str(SCREENSHOT_DIR / "0_debug_after_nav.png"), full_page=True)
        page.screenshot(path=str(SCREENSHOT_DIR / "1_detections_list.png"), full_page=True)

        rows = page.locator("a[href^='/detections/']")
        row_count = rows.count()
        check("real detections list has at least one row", row_count > 0)
        if row_count == 0:
            print("No detections for this org -- cannot verify further, stopping.")
            browser.close()
            passed = sum(1 for _, ok in CHECKS if ok)
            print(f"\n{passed}/{len(CHECKS)} checks passed")
            sys.exit(1 if passed != len(CHECKS) else 0)

        risk_pills = page.locator(
            "text=/Critical ·|High ·|Medium ·|Low ·|Not scored/"
        )
        check(
            "at least one real RiskScorePill rendered in the list (not just TriageStatePill)",
            risk_pills.count() > 0,
        )

        print("=== NAVIGATE: first detection's detail page ===")
        rows.first.click()
        page.wait_for_selector("text=Back to Detections", timeout=15000)
        page.wait_for_timeout(500)
        page.screenshot(path=str(SCREENSHOT_DIR / "2_detection_detail.png"), full_page=True)

        detail_pill = page.locator("text=/Critical ·|High ·|Medium ·|Low ·|Not scored/")
        check("RiskScorePill rendered in the detail page header", detail_pill.count() > 0)

        breakdown_heading = page.locator("text=Risk Score Breakdown")
        has_breakdown = breakdown_heading.count() > 0
        check(
            "Risk Score Breakdown section present (only when riskFactors is non-empty)",
            has_breakdown,
        )
        if has_breakdown:
            table_text = page.locator("table").last.inner_text()
            print("Risk Score Breakdown table content:\n" + table_text)
            check(
                "breakdown table has real factor rows with a Weight column",
                "Weight" in table_text and "Normalized Value" in table_text,
            )

        browser.close()

    passed = sum(1 for _, ok in CHECKS if ok)
    total = len(CHECKS)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
