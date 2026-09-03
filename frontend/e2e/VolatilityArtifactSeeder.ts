import path from "node:path";
import { fileURLToPath } from "node:url";
import { runPythonFixture } from "./pythonFixture";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SEED_SCRIPT = path.resolve(__dirname, "fixtures/seed_volatility_artifacts.py");

export type SeededArtifacts = { caseId: string; evidenceId: string; artifactIds: string[] };

/**
 * Wraps frontend/e2e/fixtures/seed_volatility_artifacts.py rather than
 * reimplementing the insert in TypeScript -- goes through the real
 * PostgresArtifactRepository, same reasoning as DetectionSeeder.
 *
 * Gap Audit Milestone AAAAA: the real end-to-end volatility3 pipeline
 * (real subprocess, real dual-emit, real OpenSearch ingestion) is already
 * verified for real against the real cridex.vmem sample in
 * poc/volatility_timeline_dual_emit/ -- a 512 MiB memory-image upload
 * through this E2E suite would be slow and heavy for what this spec
 * actually needs to prove (does the Artifacts UI render real data
 * correctly), so this seeds the same real, already-captured row shapes
 * directly, against a real evidence_id from a real (trivial) upload the
 * spec itself drives through the UI first.
 */
export class VolatilityArtifactSeeder {
  seed(
    caseId: string,
    evidenceId: string,
    orgAlias = process.env.KRONOS_E2E_SEED_ORG_ALIAS ?? "kronos-dev",
    // Milestone FFFFF: seeds the two on-demand kinds
    // (volatility.dumpfiles/volatility.registry.printkey) plus real bytes
    // in the derived-artifact MinIO bucket -- opt-in since
    // case-artifacts-ui.spec.ts asserts exactly 7 seeded kinds via this
    // same script's default (eager-only) behavior.
    includeOnDemand = false,
  ): SeededArtifacts {
    const args = [
      "--case-id",
      caseId,
      "--evidence-id",
      evidenceId,
      "--org-alias",
      orgAlias,
    ];
    if (includeOnDemand) args.push("--include-on-demand");
    return runPythonFixture<SeededArtifacts>(SEED_SCRIPT, args);
  }
}
