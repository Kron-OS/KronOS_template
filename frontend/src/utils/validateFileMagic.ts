// Kept in sync with what the backend can actually route to a parser:
// PlasoParser's extension fallback (src/external/parsers/plaso.py
// _SUPPORTED_EXTENSIONS) adds dat/hve/hiv/sqlite3 for SRUM/Amcache/
// registry hives, pf for prefetch, and txt for Nginx's .log/.txt gate.
const ALLOWED_EXTENSIONS = new Set([
  'evtx', 'json', 'jsonl', 'csv', 'log', 'txt', 'gz', 'zip',
  'sqlite', 'sqlite3', 'db', 'dat', 'hve', 'hiv', 'pf', 'e01', 'ex01', 'tar',
])

// Raw physical memory dumps (VolatilityModule, src/external/parsers/volatility.py)
// -- no standard magic bytes at a fixed offset (verified against the real
// cridex.vmem sample, see validation.py's own _MEMORY_DUMP_EXTENSIONS
// comment for the same finding on the backend side). This client-side list
// never got the corresponding entry when Volatility support shipped, so a
// real .vmem upload was rejected here as "Unsupported extension: .vmem"
// before ever reaching the server's own (correct) MagicByteValidator.
export const MEMORY_DUMP_EXTENSIONS = new Set(['vmem', 'mem', 'raw', 'dmp', 'lime'])

export const BLOCKED_EXTENSIONS = new Set([
  'exe', 'dll', 'scr', 'bat', 'cmd', 'ps1', 'js', 'vbs', 'jar', 'msi', 'com',
])

/**
 * Client-side pre-check only -- a UX optimization, not a security boundary
 * (the real, enforced check is the backend's MagicByteValidator,
 * src/application/validation.py). Kept as its own module, not inline in
 * UploadDrawer.tsx, so it can be unit-tested directly and so exporting it
 * doesn't break that component file's React Fast Refresh contract (oxlint
 * react(only-export-components)).
 */
export async function validateFileMagic(file: File): Promise<{ ok: boolean; reason?: string }> {
  const ext = file.name.split('.').pop()?.toLowerCase() ?? ''

  if (BLOCKED_EXTENSIONS.has(ext)) {
    return { ok: false, reason: `Blocked file type: .${ext}` }
  }

  // Read 262 bytes for magic byte check -- exactly enough to cover the tar
  // check below (offset 257 + 5-byte "ustar" signature = byte 261, the last
  // index in a 262-byte slice).
  const slice = file.slice(0, 262)
  const buf = await slice.arrayBuffer()
  const bytes = new Uint8Array(buf)

  // EVTX: ElfFile\x00
  if (
    bytes[0] === 0x45 && bytes[1] === 0x6c && bytes[2] === 0x66 &&
    bytes[3] === 0x46 && bytes[4] === 0x69 && bytes[5] === 0x6c &&
    bytes[6] === 0x65 && bytes[7] === 0x00
  ) {
    return { ok: true }
  }

  // GZIP: \x1f\x8b
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return { ok: true }

  // ZIP / .zip: PK\x03\x04
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
    return { ok: true }
  }

  // SQLite: "SQLite format 3\x00"
  const sqliteMagic = [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00]
  if (sqliteMagic.every((b, i) => bytes[i] === b)) return { ok: true }

  // Prefetch, MAM-compressed container: MAM\x04 / MAM\x08 / ...
  if (bytes[0] === 0x4d && bytes[1] === 0x41 && bytes[2] === 0x4d) {
    return { ok: true }
  }

  // Prefetch, uncompressed SCCA format: 4-byte version field then "SCCA"
  // at offset 4 (e.g. Windows 10 version-17 files: \x11\x00\x00\x00SCCA).
  // Real-world prefetch is frequently not MAM-compressed — this check was
  // missing here even after the backend (PlasoParser) learned to accept
  // it, so real .pf files kept getting rejected client-side with
  // "Unsupported extension: .pf" before ever reaching the server.
  if (bytes[4] === 0x53 && bytes[5] === 0x43 && bytes[6] === 0x43 && bytes[7] === 0x41) {
    return { ok: true }
  }

  // Windows Registry hive: "regf"
  if (bytes[0] === 0x72 && bytes[1] === 0x65 && bytes[2] === 0x67 && bytes[3] === 0x66) {
    return { ok: true }
  }

  // EWF disk image (E01/Ex01) — KAPE/forensic-imaging tool output, routed
  // server-side through PlasoParser's dfVFS whole-image path (backend's
  // MagicByteValidator, src/application/validation.py, already accepts this
  // signature by magic bytes alone with no extension gate at all). This
  // client-side check was never added when that backend support shipped
  // (commit 44a9089), so real .E01 files were rejected here as "Unsupported
  // extension: .e01" before ever reaching the server.
  const ewfMagic = [0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]
  if (ewfMagic.every((b, i) => bytes[i] === b)) return { ok: true }

  // tar (ustar/GNU/PAX) -- container for tar-wrapped disk-image bundles
  // (roadmap E1: a forensic2.E01-named evidence file that was actually a
  // tar of image.dd + memory.dmp), routed server-side to TarArchiveParser.
  // Real POSIX "ustar" 5-byte prefix at the fixed header offset 257 --
  // mirrors validation.py's own _MAGIC_TABLE entry exactly. This check was
  // missing here even after backend tar support shipped (Gap Audit
  // Milestone TT), so a real .tar file was rejected client-side as
  // "Unsupported extension: .tar" before ever reaching the server -- same
  // class of drift as the SCCA prefetch and EWF gaps already fixed above.
  const ustarMagic = [0x75, 0x73, 0x74, 0x61, 0x72]
  if (ustarMagic.every((b, i) => bytes[257 + i] === b)) return { ok: true }

  // Text-based formats (json, jsonl, csv, log, txt) — check for printable ASCII start
  if (['json', 'jsonl', 'csv', 'log', 'txt'].includes(ext)) {
    const isText = bytes.slice(0, 8).every((b) => b >= 0x09 && b <= 0x7e)
    if (isText) return { ok: true }
  }

  // Raw memory dumps -- no verified magic bytes exist for this format
  // family (see MEMORY_DUMP_EXTENSIONS's own comment above); accept on
  // extension alone, same bypass shape as the text-format check above.
  // Checked BEFORE the MZ-header reject below: raw physical memory is
  // arbitrary content at offset 0 and can coincidentally start with
  // 0x4d 0x5a without being a Windows executable at all.
  if (MEMORY_DUMP_EXTENSIONS.has(ext)) return { ok: true }

  // MZ header (Windows PE) — always reject
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
    return { ok: false, reason: 'Windows executable files are not accepted' }
  }

  if (!ALLOWED_EXTENSIONS.has(ext)) {
    return { ok: false, reason: `Unsupported extension: .${ext}` }
  }

  return { ok: true }
}
