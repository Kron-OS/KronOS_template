import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLOUDTRAIL_SAMPLE = path.resolve(__dirname, "../../tests/fixtures/samples/real/aws_cloudtrail.jsonl");

/**
 * Flow tier: minimizable evidence upload + quit-warning. Real fixtures PUT
 * to MinIO in well under a second, giving no deterministic window to
 * observe live progress/minimize mid-upload -- `delayPresignedPut()`
 * injects a real artificial delay on the real presigned PUT request (not a
 * mock of the upload itself) so these assertions are reliable rather than
 * racing real network speed.
 */
test("minimizing an in-progress upload shows a live badge and survives navigating away", async ({
  casesPageAsCaseLead,
  page,
}) => {
  const title = `E2E minimize spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-MIN-${Date.now()}`);

  await detail.delayPresignedPut(3000);
  await detail.startUploadWithoutWaiting(CLOUDTRAIL_SAMPLE);

  await detail.minimizeUpload();
  // The drawer itself must be gone from the DOM (not just visually
  // hidden) -- the hard constraint uploadEvidence()/other specs depend on.
  await expect(page.locator("#evidence-file-input")).toHaveCount(0);
  await expect(detail.uploadBadge()).toBeVisible();

  // Real client-side SPA navigation (a <Link> click, via history.pushState)
  // -- NOT page.goto(), which forces a full document reload and would tear
  // down the whole JS runtime/store, i.e. exactly the "survives navigating
  // away" claim being tested here would trivially fail against the wrong
  // kind of navigation.
  await page.click("text=Cases");
  await page.waitForURL("**/cases");
  await expect(detail.uploadBadge()).toBeVisible();
  await expect(detail.uploadBadge()).toContainText(/Uploading 1 file/);

  await detail.reopenFromBadge();
  await page.waitForSelector("text=Done", { timeout: 30000 });
});

test("no beforeunload warning once the upload is done", async ({ casesPageAsCaseLead, page }) => {
  const title = `E2E no-warning spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-NOWARN-${Date.now()}`);

  // Deliberately does NOT close the drawer (unlike uploadEvidence()) --
  // the finished job stays tracked in the store (status: 'done', not
  // removed) so this actually exercises "a completed job present must not
  // block navigation," not the trivially-true "zero jobs at all" case.
  await detail.startUploadWithoutWaiting(CLOUDTRAIL_SAMPLE);
  await page.waitForSelector("text=Done", { timeout: 30000 });

  let dialogFired = false;
  page.on("dialog", (dialog) => {
    dialogFired = true;
    void dialog.dismiss();
  });
  await page.reload();
  await page.waitForTimeout(500);

  expect(dialogFired).toBe(false);
});

test("beforeunload warns while a real job is still uploading", async ({ casesPageAsCaseLead, page }) => {
  const title = `E2E warning spec ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-WARN-${Date.now()}`);

  await detail.delayPresignedPut(5000);
  await detail.startUploadWithoutWaiting(CLOUDTRAIL_SAMPLE);

  // Real browsers never render custom beforeunload text (a security
  // measure) -- only the fact that a dialog fires is assertable.
  // page.close({ runBeforeUnload: true }) is Playwright's documented,
  // reliable trigger for this real dialog -- page.reload() was tried
  // first and, empirically against this real Chromium build, never
  // surfaced the dialog event at all (a real CDP/automation quirk, not
  // something to paper over with a longer timeout).
  const dialogPromise = page.waitForEvent("dialog", { timeout: 10000 });
  const closePromise = page.close({ runBeforeUnload: true });
  const dialog = await dialogPromise;

  expect(dialog.type()).toBe("beforeunload");
  await dialog.accept();
  await closePromise;
});
