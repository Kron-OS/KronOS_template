import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "./fixtures";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Real diagnosis fix (case 43097ab0-aae3-4968-915b-8f0229ac3865): a genuine
 * memory image uploaded under an extension MagicByteValidator doesn't
 * recognise (raw memory has no reliable magic bytes at all -- confirmed
 * live against the real ch2.dat/ch2.dmp bytes on that case) was flatly
 * rejected with "validation_failed" and no way for the analyst to say
 * "trust me, this is memory." This spec proves the new "This is a memory
 * image" checkbox (UploadDrawer.tsx) reaches the real backend override
 * end to end: same synthetic, non-magic binary content under an extension
 * on neither the client's nor the server's allowlist, once without the
 * checkbox (reproduces the original rejection) and once with it (passes).
 */
const UNRECOGNIZED_EXT_SAMPLE = path.resolve(
  __dirname,
  "../../tests/fixtures/samples/synthetic_memory.unknownext",
);

test("upload without the memory-image checkbox is rejected under an unrecognized extension", async ({
  page,
  casesPageAsCaseLead,
}) => {
  const title = `E2E declared-format spec (reject) ${Date.now()}`;
  await casesPageAsCaseLead.createCase(title, `E2E-DECLFMT-REJ-${Date.now()}`);

  await page.click("text=Upload Evidence");
  await page.waitForSelector("#evidence-file-input", { timeout: 10000 });
  await page.setInputFiles("#evidence-file-input", UNRECOGNIZED_EXT_SAMPLE);
  await page.getByRole("button", { name: "Upload", exact: true }).click();

  // Real, live-reproduced original bug: validateFileMagic (a client-side
  // UX optimization mirroring the backend's own MagicByteValidator) runs
  // inside runUpload(), triggered only once Upload is clicked -- the job
  // is created as "uploading" then immediately flips to this rejection,
  // never reaching the network at all.
  await expect(page.getByText(/Unsupported extension/i)).toBeVisible({ timeout: 10000 });
});

test("upload with the memory-image checkbox reaches Done under the same unrecognized extension", async ({
  page,
  casesPageAsCaseLead,
}) => {
  const title = `E2E declared-format spec (accept) ${Date.now()}`;
  const detail = await casesPageAsCaseLead.createCase(title, `E2E-DECLFMT-ACC-${Date.now()}`);

  await page.click("text=Upload Evidence");
  await page.waitForSelector("#evidence-file-input", { timeout: 10000 });
  await page.setInputFiles("#evidence-file-input", UNRECOGNIZED_EXT_SAMPLE);

  await page.getByLabel(/This is a memory image/i).check();
  await page.getByRole("button", { name: "Upload", exact: true }).click();

  await page.waitForSelector("text=Done", { timeout: 30000 });

  const { seenStates, terminal } = await detail.watchEvidenceStateLive(
    "synthetic_memory.unknownext",
  );
  expect(terminal, `observed state sequence: ${seenStates.join(" -> ")}`).not.toBe("Error");
});
