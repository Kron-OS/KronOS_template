import { describe, it, expect } from 'vitest'
import { validateFileMagic } from '../utils/validateFileMagic'

/**
 * Gap Audit Milestone TT: validateFileMagic() is a client-side UX pre-check
 * only (the real security boundary is the backend's MagicByteValidator,
 * src/application/validation.py) -- but this exact function has already
 * drifted out of sync with real backend parser support twice before (SCCA
 * prefetch, EWF), each time silently rejecting a real, backend-supported
 * artifact with a misleading "Unsupported extension" error before it ever
 * reached the server. This is the third instance: a real .tar file (backend
 * has a dedicated TarArchiveParser, and validation.py's own _MAGIC_TABLE
 * checks for the POSIX "ustar" 5-byte signature at header offset 257) had
 * no client-side magic-byte check at all.
 */

function fileWithBytes(name: string, bytes: number[], padTo = 262): File {
  const buf = new Uint8Array(padTo)
  buf.set(bytes.slice(0, padTo))
  return new File([buf], name)
}

describe('validateFileMagic (Gap Audit Milestone TT: tar/ustar support)', () => {
  it('accepts a real ustar tar header regardless of extension', async () => {
    const bytes = new Array(262).fill(0)
    // POSIX ustar magic at the real, fixed header offset 257.
    const ustar = [0x75, 0x73, 0x74, 0x61, 0x72]
    ustar.forEach((b, i) => {
      bytes[257 + i] = b
    })
    const file = fileWithBytes('evidence.tar', bytes)

    const result = await validateFileMagic(file)

    expect(result.ok).toBe(true)
  })

  it('accepts a GNU tar header ("ustar  \\0" variant) at the same offset', async () => {
    const bytes = new Array(262).fill(0)
    const ustar = [0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00]
    ustar.forEach((b, i) => {
      bytes[257 + i] = b
    })
    const file = fileWithBytes('mislabeled.E01', bytes)

    const result = await validateFileMagic(file)

    expect(result.ok).toBe(true)
  })

  it('still rejects an unrecognized extension with no matching magic bytes', async () => {
    const file = fileWithBytes('evidence.xyz', new Array(262).fill(0))

    const result = await validateFileMagic(file)

    expect(result.ok).toBe(false)
    expect(result.reason).toContain('Unsupported extension')
  })

  it('still rejects a blocked extension outright', async () => {
    const file = fileWithBytes('malware.exe', new Array(262).fill(0))

    const result = await validateFileMagic(file)

    expect(result.ok).toBe(false)
    expect(result.reason).toContain('Blocked file type')
  })

  it('still accepts a real EVTX header (pre-existing behavior, not regressed)', async () => {
    const bytes = new Array(262).fill(0)
    const evtx = [0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00]
    evtx.forEach((b, i) => {
      bytes[i] = b
    })
    const file = fileWithBytes('system.evtx', bytes)

    const result = await validateFileMagic(file)

    expect(result.ok).toBe(true)
  })
})
