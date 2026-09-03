import { useState } from 'react'
import type { Artifact } from '../types'

/**
 * Gap Audit Milestone AAAAA: kind-aware rendering for StructuredArtifact
 * content, per the design conversation's "scenario 4" decision. `content`
 * is intentionally opaque (src/domain/artifact.py) -- these components
 * give real kinds this platform emits real, curated shape; anything else
 * falls back to a generic table (or raw JSON if it isn't even row-shaped),
 * so a future module's new `kind` renders usably with zero new frontend
 * code, not a blank/broken view.
 *
 * Gap Audit Milestone DDDDD: extended for the 5 new eager Volatility
 * plugins (Milestone CCCCC's backend work) -- `dlllist`/`filescan`/
 * `registry.hivelist` get small dedicated views (hides volatility3's own
 * always-"Disabled" `File output` column, formats addresses as hex --
 * real DFIR convention); `cmdline`'s real row shape
 * (`{PID, Process, Args}`) already renders adequately through
 * `GenericArtifactView`, so no dedicated component was added for it (per
 * the approved plan's own "don't build one if the generic table already
 * looks right" guidance). `malfind` gets a genuinely new, visually
 * distinct "suspicious" card layout, not a table -- see `MalfindView`.
 */

interface ProcessRow {
  PID?: number
  PPID?: number
  ImageFileName?: string
  CreateTime?: string | null
  ExitTime?: string | null
  Threads?: number | null
  Handles?: number | null
  SessionId?: number | null
  __children?: ProcessRow[]
  [key: string]: unknown
}

interface DllRow {
  PID?: number
  Process?: string
  Name?: string
  Path?: string
  Base?: number
  Size?: number
  [key: string]: unknown
}

export interface FileScanRow {
  Offset?: number
  Name?: string
  [key: string]: unknown
}

export interface HiveListRow {
  Offset?: number
  FileFullPath?: string
  [key: string]: unknown
}

interface MalfindRow {
  PID?: number
  Process?: string
  'Start VPN'?: number
  'End VPN'?: number
  Protection?: string
  CommitCharge?: number
  Hexdump?: string
  [key: string]: unknown
}

interface RegistryPrintkeyRow {
  Name?: string
  Type?: string
  Data?: string
  Key?: string
  Volatile?: boolean
  'Last Write Time'?: string
  [key: string]: unknown
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatHex(value: unknown): string {
  return typeof value === 'number' ? `0x${value.toString(16)}` : formatCell(value)
}

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  // A nested object/array (e.g. a matched event's own ECS-shaped `source`,
  // Gap Audit Milestone BBBBB) would otherwise stringify to the useless
  // "[object Object]" -- JSON.stringify gives a real, inspectable value
  // instead. Existing Volatility rows never hit this branch (their fields
  // are all primitives already), so this is additive, not a behavior change.
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function ProcessTreeNode({ row, depth }: { row: ProcessRow; depth: number }) {
  const [collapsed, setCollapsed] = useState(false)
  const children = Array.isArray(row.__children) ? row.__children : []

  return (
    <li>
      <div
        className="flex items-center gap-2 rounded px-2 py-1 text-sm hover:bg-gray-100 dark:hover:bg-gray-800"
        style={{ paddingLeft: `${depth * 1.25}rem` }}
      >
        {children.length > 0 ? (
          <button
            type="button"
            onClick={() => setCollapsed((c) => !c)}
            aria-label={collapsed ? 'Expand' : 'Collapse'}
            className="w-4 shrink-0 text-gray-500 hover:text-gray-800 dark:hover:text-gray-200"
          >
            {collapsed ? '▸' : '▾'}
          </button>
        ) : (
          <span className="w-4 shrink-0" />
        )}
        <span className="font-mono text-xs text-gray-500">{formatCell(row.PID)}</span>
        <span className="text-gray-800 dark:text-gray-200">{formatCell(row.ImageFileName)}</span>
        {row.CreateTime && (
          <span className="text-xs text-gray-500">{new Date(row.CreateTime).toLocaleString()}</span>
        )}
      </div>
      {!collapsed && children.length > 0 && (
        <ul>
          {children.map((child, i) => (
            <ProcessTreeNode key={`${child.PID ?? i}-${i}`} row={child} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  )
}

export function ProcessTreeView({ rows }: { rows: ProcessRow[] }) {
  if (rows.length === 0) {
    return <p className="text-sm text-gray-500">No processes found by this plugin.</p>
  }
  return (
    <ul className="rounded border border-gray-200 py-1 dark:border-gray-800">
      {rows.map((row, i) => (
        <ProcessTreeNode key={`${row.PID ?? i}-${i}`} row={row} depth={0} />
      ))}
    </ul>
  )
}

const PSSCAN_COLUMNS: { key: keyof ProcessRow; label: string }[] = [
  { key: 'PID', label: 'PID' },
  { key: 'PPID', label: 'PPID' },
  { key: 'ImageFileName', label: 'Image name' },
  { key: 'CreateTime', label: 'Created' },
  { key: 'ExitTime', label: 'Exited' },
  { key: 'Threads', label: 'Threads' },
  { key: 'SessionId', label: 'Session' },
]

export function ProcessTableView({ rows }: { rows: ProcessRow[] }) {
  if (rows.length === 0) {
    return <p className="text-sm text-gray-500">No processes found by this plugin.</p>
  }
  return (
    <div className="overflow-x-auto rounded border border-gray-200 dark:border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
            {PSSCAN_COLUMNS.map((col) => (
              <th key={String(col.key)} className="px-3 py-2 font-medium">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
          {rows.map((row, i) => (
            <tr key={`${row.PID ?? i}-${i}`} className="hover:bg-gray-100/50 dark:hover:bg-gray-900/30">
              {PSSCAN_COLUMNS.map((col) => {
                const raw = row[col.key as string]
                const isTime = (col.key === 'CreateTime' || col.key === 'ExitTime') && typeof raw === 'string'
                return (
                  <td key={String(col.key)} className="px-3 py-2 text-gray-700 dark:text-gray-300">
                    {isTime ? new Date(raw as string).toLocaleString() : formatCell(raw)}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const DLLLIST_COLUMNS: { key: keyof DllRow; label: string; hex?: boolean }[] = [
  { key: 'PID', label: 'PID' },
  { key: 'Process', label: 'Process' },
  { key: 'Name', label: 'DLL name' },
  { key: 'Path', label: 'Path' },
  { key: 'Base', label: 'Base', hex: true },
  { key: 'Size', label: 'Size' },
]

export function DllListView({ rows }: { rows: DllRow[] }) {
  if (rows.length === 0) {
    return <p className="text-sm text-gray-500">No loaded modules found by this plugin.</p>
  }
  return (
    <div className="overflow-x-auto rounded border border-gray-200 dark:border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
            {DLLLIST_COLUMNS.map((col) => (
              <th key={String(col.key)} className="px-3 py-2 font-medium">
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
          {rows.map((row, i) => (
            <tr
              key={`${row.PID ?? i}-${row.Base ?? i}-${i}`}
              className="hover:bg-gray-100/50 dark:hover:bg-gray-900/30"
            >
              {DLLLIST_COLUMNS.map((col) => (
                <td
                  key={String(col.key)}
                  className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300"
                >
                  {col.hex ? formatHex(row[col.key as string]) : formatCell(row[col.key as string])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

const FILESCAN_COLUMNS: { key: keyof FileScanRow; label: string; hex?: boolean }[] = [
  { key: 'Offset', label: 'Offset', hex: true },
  { key: 'Name', label: 'Path' },
]

/** Milestone EEEEE/FFFFF: FileScanView is the entry point for the
 * on-demand "Extract this file" action -- windows.filescan's own `Offset`
 * column is the real PHYSICAL address windows.dumpfiles needs
 * (poc/volatility_dumpfiles/'s decisive finding, NOT a virtual address),
 * so a row here can drive the extraction request directly, with no
 * additional lookup. `onExtract` is optional so this view still works
 * read-only wherever it's reused without wiring the on-demand path. */
export function FileScanView({
  rows,
  onExtract,
  extractingOffsets,
  extractedOffsets,
  failedOffsets,
}: {
  rows: FileScanRow[]
  onExtract?: (row: FileScanRow) => void
  extractingOffsets?: Set<number>
  extractedOffsets?: Set<number>
  /** Milestone FFFFF, real bug found via a live browser run: a targeted
   * physaddr can genuinely have no recoverable bytes (a real, honest
   * volatility3 outcome, not an error) -- without this, a failed
   * extraction left the button stuck on "Extracting…" forever. */
  failedOffsets?: Set<number>
}) {
  if (rows.length === 0) {
    return <p className="text-sm text-gray-500">No file objects found resident in memory.</p>
  }
  return (
    <div className="overflow-x-auto rounded border border-gray-200 dark:border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
            {FILESCAN_COLUMNS.map((col) => (
              <th key={String(col.key)} className="px-3 py-2 font-medium">
                {col.label}
              </th>
            ))}
            {onExtract && <th className="px-3 py-2 font-medium">Child Files</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
          {rows.map((row, i) => {
            const offset = typeof row.Offset === 'number' ? row.Offset : null
            const isExtracting = offset !== null && extractingOffsets?.has(offset)
            const isExtracted = offset !== null && extractedOffsets?.has(offset)
            const hasFailed = offset !== null && failedOffsets?.has(offset)
            return (
              <tr key={`${row.Offset ?? i}-${i}`} className="hover:bg-gray-100/50 dark:hover:bg-gray-900/30">
                {FILESCAN_COLUMNS.map((col) => (
                  <td
                    key={String(col.key)}
                    className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300"
                  >
                    {col.hex ? formatHex(row[col.key as string]) : formatCell(row[col.key as string])}
                  </td>
                ))}
                {onExtract && (
                  <td className="px-3 py-2">
                    {offset === null ? (
                      '—'
                    ) : isExtracted ? (
                      <span className="text-xs font-medium text-green-700 dark:text-green-400">
                        Extracted
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onExtract(row)}
                        disabled={isExtracting}
                        title={hasFailed ? 'No bytes recoverable at this offset — try another file' : undefined}
                        className="rounded px-2 py-1 text-xs font-medium text-indigo-600 hover:bg-indigo-50 disabled:cursor-not-allowed disabled:text-gray-400 dark:text-indigo-400 dark:hover:bg-indigo-950/40 dark:disabled:text-gray-600"
                      >
                        {isExtracting ? 'Extracting…' : hasFailed ? 'Failed — retry?' : 'Extract'}
                      </button>
                    )}
                  </td>
                )}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

export function HiveListView({ rows }: { rows: HiveListRow[] }) {
  if (rows.length === 0) {
    return <p className="text-sm text-gray-500">No registry hives found in this memory image.</p>
  }
  return (
    <div className="overflow-x-auto rounded border border-gray-200 dark:border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
            <th className="px-3 py-2 font-medium">Offset</th>
            <th className="px-3 py-2 font-medium">Hive path</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
          {rows.map((row, i) => (
            <tr key={`${row.Offset ?? i}-${i}`} className="hover:bg-gray-100/50 dark:hover:bg-gray-900/30">
              <td className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                {formatHex(row.Offset)}
              </td>
              <td className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                {row.FileFullPath ? row.FileFullPath : '(path not recovered)'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Real, reproduced signal, Gap Audit Milestone CCCCC: a real 1.6GB user
 * memory image produced 4 real windows.malware.malfind.Malfind hits,
 * including one PAGE_EXECUTE_READWRITE region inside explorer.exe -- the
 * classic code-injection tell. This is the single highest-signal "something
 * is wrong here" plugin this platform runs, so it gets a genuinely
 * different, visually distinct card layout (amber/red accent) rather than
 * folding into the same neutral-gray table every other kind uses -- an
 * analyst should never have to read column headers to notice this is the
 * "suspicious" view. */
function MalfindCard({ row }: { row: MalfindRow }) {
  const [showHexdump, setShowHexdump] = useState(false)
  const isWritableExecutable = row.Protection?.includes('EXECUTE') && row.Protection?.includes('WRITE')

  return (
    <div
      className={`rounded-lg border p-4 ${
        isWritableExecutable
          ? 'border-red-300 bg-red-50 dark:border-red-900 dark:bg-red-950/30'
          : 'border-amber-300 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/20'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <p
          className={`text-sm font-semibold ${
            isWritableExecutable
              ? 'text-red-800 dark:text-red-300'
              : 'text-amber-800 dark:text-amber-300'
          }`}
        >
          {formatCell(row.Process)} <span className="font-mono text-xs">(PID {formatCell(row.PID)})</span>
        </p>
        {row.Protection && (
          <span
            className={`shrink-0 rounded px-2 py-0.5 font-mono text-xs font-medium ${
              isWritableExecutable
                ? 'bg-red-200 text-red-900 dark:bg-red-900/60 dark:text-red-200'
                : 'bg-amber-200 text-amber-900 dark:bg-amber-900/60 dark:text-amber-200'
            }`}
          >
            {row.Protection}
          </span>
        )}
      </div>
      <p className="mt-1.5 font-mono text-xs text-gray-600 dark:text-gray-400">
        {formatHex(row['Start VPN'])} – {formatHex(row['End VPN'])}
        {row.CommitCharge !== undefined && ` · commit charge ${formatCell(row.CommitCharge)}`}
      </p>
      {row.Hexdump && (
        <div className="mt-2">
          <button
            type="button"
            onClick={() => setShowHexdump((v) => !v)}
            className="text-xs font-medium text-indigo-600 hover:underline dark:text-indigo-400"
          >
            {showHexdump ? 'Hide' : 'Show'} memory bytes
          </button>
          {showHexdump && (
            <pre className="mt-1.5 overflow-x-auto rounded border border-gray-200 bg-white p-2 font-mono text-[10px] text-gray-700 dark:border-gray-800 dark:bg-gray-950 dark:text-gray-300">
              {row.Hexdump}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

export function MalfindView({ rows }: { rows: MalfindRow[] }) {
  if (rows.length === 0) {
    return (
      <p className="rounded-lg border border-gray-200 p-4 text-sm text-gray-500 dark:border-gray-800">
        No injected/suspicious memory regions detected.
      </p>
    )
  }
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs font-medium text-gray-500">
        {rows.length} suspicious region{rows.length === 1 ? '' : 's'} found
      </p>
      {rows.map((row, i) => (
        <MalfindCard key={`${row.PID ?? i}-${row['Start VPN'] ?? i}-${i}`} row={row} />
      ))}
    </div>
  )
}

/** Milestone EEEEE/FFFFF: the user's own "child files" phrase -- lists
 * every real windows.dumpfiles extraction result for the selected evidence
 * file. Unlike every other kind, each `volatility.dumpfiles`
 * StructuredArtifact IS one row already (one real extracted file, not a
 * `content.rows` array) -- ArtifactsTab passes the raw, unmerged artifact
 * list here rather than routing through the shared row-merge path. Shows a
 * real SHA-256 plus a disabled, tooltipped VirusTotal placeholder (UI-only
 * per the plan's "eventually" -- content.enrichment stays `{}` until a
 * real lookup pass exists). */
export function DumpFilesView({
  artifacts,
  onDownload,
}: {
  artifacts: Artifact[]
  onDownload: (artifactId: string, filename: string) => void
}) {
  if (artifacts.length === 0) {
    return (
      <p className="text-sm text-gray-500">
        No files extracted yet. Open "Files in Memory" and click Extract next to a real file to pull
        its bytes here.
      </p>
    )
  }
  return (
    <div className="overflow-x-auto rounded border border-gray-200 dark:border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
            <th className="px-3 py-2 font-medium">Filename</th>
            <th className="px-3 py-2 font-medium">Size</th>
            <th className="px-3 py-2 font-medium">SHA-256</th>
            <th className="px-3 py-2 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
          {artifacts.map((artifact) => {
            const filename =
              typeof artifact.content.filename === 'string' ? artifact.content.filename : artifact.id
            const sizeBytes =
              typeof artifact.content.size_bytes === 'number' ? artifact.content.size_bytes : null
            const sha256 = typeof artifact.content.sha256 === 'string' ? artifact.content.sha256 : null
            return (
              <tr key={artifact.id} className="hover:bg-gray-100/50 dark:hover:bg-gray-900/30">
                <td className="px-3 py-2 text-gray-700 dark:text-gray-300">{filename}</td>
                <td className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                  {sizeBytes !== null ? formatBytes(sizeBytes) : '—'}
                </td>
                <td className="max-w-[16rem] truncate px-3 py-2 font-mono text-xs text-gray-500">
                  {sha256 ?? '—'}
                </td>
                <td className="px-3 py-2">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => onDownload(artifact.id, filename)}
                      className="rounded px-2 py-1 text-xs font-medium text-indigo-600 hover:bg-indigo-50 dark:text-indigo-400 dark:hover:bg-indigo-950/40"
                    >
                      Download
                    </button>
                    <span
                      title="Check reputation — VirusTotal coming soon"
                      className="cursor-not-allowed rounded bg-gray-100 px-2 py-1 text-xs text-gray-600 dark:bg-gray-800 dark:text-gray-400"
                    >
                      Check reputation
                    </span>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function HiveBreadcrumb({
  hivePath,
  path,
  onNavigate,
}: {
  hivePath: string
  path: string[]
  onNavigate: (depth: number) => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-1 font-mono text-xs text-gray-500">
      <button type="button" onClick={() => onNavigate(0)} className="hover:underline">
        {hivePath || 'hive root'}
      </button>
      {path.map((segment, i) => (
        <span key={`${segment}-${i}`} className="flex items-center gap-1">
          <span>\</span>
          <button type="button" onClick={() => onNavigate(i + 1)} className="hover:underline">
            {segment}
          </button>
        </span>
      ))}
    </div>
  )
}

/** Milestone EEEEE/FFFFF: interactive, one-level-at-a-time registry
 * browser (poc/volatility_registry_printkey/'s real, verified design --
 * scoped, non-recursive `printkey` calls, ~0.35s each, vs. >200s
 * unscoped). A real `windows.registry.printkey` call's own `key` parameter
 * takes the FULL backslash-joined path from the hive root (re-verified
 * live against Challenge.raw: `"ControlSet001\\Control"` returns Control's
 * own children directly) -- not an incremental one-level name -- so `path`
 * here is the full breadcrumb, joined fresh on every request. Each
 * (hiveOffset, key) combination the user has already drilled into is its
 * own real `volatility.registry.printkey` StructuredArtifact; this
 * component looks up the one matching its current position rather than
 * merging them (each represents a different, real point in the registry
 * tree -- merging would interleave unrelated keys' rows into one table). */
export function RegistryBrowser({
  hives,
  printkeyArtifacts,
  onRequestKey,
  pendingKeys,
  failedKeys,
}: {
  hives: HiveListRow[]
  printkeyArtifacts: Artifact[]
  onRequestKey: (hiveOffset: number, key: string | null) => void
  pendingKeys: Set<string>
  /** Milestone FFFFF: a real printkey request can genuinely fail
   * asynchronously (e.g. a real LayerException -- poc/volatility_registry_printkey/)
   * with nothing to ever resolve "Loading…" on its own; the container
   * times a pending request out and reports it here so the UI can offer a
   * real retry instead of spinning forever. */
  failedKeys?: Set<string>
}) {
  const [selectedHive, setSelectedHive] = useState<HiveListRow | null>(null)
  const [path, setPath] = useState<string[]>([])

  if (hives.length === 0) {
    return <p className="text-sm text-gray-500">No registry hives found in this memory image.</p>
  }

  const selectHive = (hive: HiveListRow) => {
    setSelectedHive(hive)
    setPath([])
    if (typeof hive.Offset === 'number') onRequestKey(hive.Offset, null)
  }

  if (!selectedHive) {
    return (
      <div>
        <p className="mb-2 text-xs text-gray-500">Select a hive to browse its real keys on demand.</p>
        <ul className="flex flex-col gap-1">
          {hives.map((hive, i) => (
            <li key={hive.Offset ?? i}>
              <button
                type="button"
                onClick={() => selectHive(hive)}
                className="rounded px-2 py-1 text-left font-mono text-sm text-indigo-600 hover:bg-indigo-50 dark:text-indigo-400 dark:hover:bg-indigo-950/40"
              >
                {hive.FileFullPath || '(path not recovered)'}
              </button>
            </li>
          ))}
        </ul>
      </div>
    )
  }

  const hiveOffset = selectedHive.Offset
  if (typeof hiveOffset !== 'number') return null

  const drillInto = (name: string) => {
    const nextPath = [...path, name]
    setPath(nextPath)
    onRequestKey(hiveOffset, nextPath.join('\\'))
  }
  const navigateTo = (depth: number) => {
    const nextPath = path.slice(0, depth)
    setPath(nextPath)
    onRequestKey(hiveOffset, nextPath.length > 0 ? nextPath.join('\\') : null)
  }

  const currentKey = path.length > 0 ? path.join('\\') : null
  const cacheKey = `${hiveOffset}|${currentKey ?? ''}`
  const isPending = pendingKeys.has(cacheKey)
  const hasFailed = failedKeys?.has(cacheKey) ?? false
  const matching = printkeyArtifacts.find(
    (a) => a.content.hive_offset === hiveOffset && (a.content.key ?? null) === currentKey,
  )
  const rows =
    matching && Array.isArray(matching.content.rows)
      ? (matching.content.rows as RegistryPrintkeyRow[])
      : null

  return (
    <div>
      <div className="mb-3 flex items-center justify-between gap-2">
        <HiveBreadcrumb
          hivePath={selectedHive.FileFullPath ?? ''}
          path={path}
          onNavigate={navigateTo}
        />
        <button
          type="button"
          onClick={() => {
            setSelectedHive(null)
            setPath([])
          }}
          className="shrink-0 text-xs text-gray-500 hover:underline"
        >
          Change hive
        </button>
      </div>
      {isPending && !rows && <p className="text-sm text-gray-500">Loading real registry data…</p>}
      {!isPending && hasFailed && !rows && (
        <p className="text-sm text-red-600 dark:text-red-400">
          Failed to load this key.{' '}
          <button
            type="button"
            onClick={() => onRequestKey(hiveOffset, currentKey)}
            className="font-medium text-indigo-600 hover:underline dark:text-indigo-400"
          >
            Retry
          </button>
        </p>
      )}
      {!isPending && !hasFailed && !rows && (
        <button
          type="button"
          onClick={() => onRequestKey(hiveOffset, currentKey)}
          className="text-sm text-indigo-600 hover:underline dark:text-indigo-400"
        >
          Load this key
        </button>
      )}
      {rows && rows.length === 0 && (
        <p className="text-sm text-gray-500">This key has no real subkeys or values.</p>
      )}
      {rows && rows.length > 0 && (
        <div className="overflow-x-auto rounded border border-gray-200 dark:border-gray-800">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
                <th className="px-3 py-2 font-medium">Name</th>
                <th className="px-3 py-2 font-medium">Type</th>
                <th className="px-3 py-2 font-medium">Data</th>
                <th className="px-3 py-2 font-medium">Last write time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
              {rows.map((row, i) => {
                const isKey = row.Type === 'Key'
                return (
                  <tr key={`${row.Name ?? i}-${i}`} className="hover:bg-gray-100/50 dark:hover:bg-gray-900/30">
                    <td className="px-3 py-2 font-mono text-xs">
                      {isKey ? (
                        <button
                          type="button"
                          onClick={() => drillInto(String(row.Name))}
                          className="text-indigo-600 hover:underline dark:text-indigo-400"
                        >
                          {formatCell(row.Name)}
                        </button>
                      ) : (
                        <span className="text-gray-700 dark:text-gray-300">{formatCell(row.Name)}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                      {formatCell(row.Type)}
                    </td>
                    <td className="max-w-xs truncate px-3 py-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                      {formatCell(row.Data)}
                    </td>
                    <td className="px-3 py-2 text-xs text-gray-500">
                      {row['Last Write Time'] ? new Date(row['Last Write Time']).toLocaleString() : '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/** Generic fallback for any kind this platform doesn't have a dedicated
 * renderer for yet -- a real table built from whatever keys the first row
 * has, or raw JSON if content isn't even row-shaped. */
export function GenericArtifactView({ content }: { content: Record<string, unknown> }) {
  const rows = Array.isArray(content.rows) ? (content.rows as Record<string, unknown>[]) : null

  if (!rows) {
    return (
      <pre className="overflow-x-auto rounded border border-gray-200 bg-gray-50 p-3 text-xs text-gray-700 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-300">
        {JSON.stringify(content, null, 2)}
      </pre>
    )
  }
  if (rows.length === 0) {
    return <p className="text-sm text-gray-500">No rows in this artifact.</p>
  }
  const columns = Object.keys(rows[0]).filter((k) => k !== '__children')

  return (
    <div className="overflow-x-auto rounded border border-gray-200 dark:border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200 bg-gray-100/50 text-left text-xs text-gray-600 dark:border-gray-800 dark:bg-gray-900/50 dark:text-gray-400">
            {columns.map((col) => (
              <th key={col} className="px-3 py-2 font-medium">
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-800">
          {rows.map((row, i) => (
            <tr key={i} className="hover:bg-gray-100/50 dark:hover:bg-gray-900/30">
              {columns.map((col) => (
                <td key={col} className="px-3 py-2 text-gray-700 dark:text-gray-300">
                  {formatCell(row[col])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

/** Dispatches an Artifact to the right kind-aware renderer by its real
 * `kind` string. Unrecognized kinds -- including any future non-Volatility
 * module's own -- fall back to GenericArtifactView, never a blank view. */
export function ArtifactContent({
  artifact,
  onExtract,
  extractingOffsets,
  extractedOffsets,
  failedOffsets,
}: {
  artifact: Artifact
  /** Milestone EEEEE/FFFFF: only meaningful for volatility.filescan --
   * wires FileScanView's real "Extract this file" action. Optional so
   * ArtifactContent still works read-only wherever the on-demand path
   * isn't available. */
  onExtract?: (row: FileScanRow) => void
  extractingOffsets?: Set<number>
  extractedOffsets?: Set<number>
  failedOffsets?: Set<number>
}) {
  const rows = Array.isArray(artifact.content.rows) ? artifact.content.rows : null

  if (artifact.kind === 'volatility.pstree' && rows) {
    return <ProcessTreeView rows={rows as ProcessRow[]} />
  }
  if (artifact.kind === 'volatility.psscan' && rows) {
    return <ProcessTableView rows={rows as ProcessRow[]} />
  }
  if (artifact.kind === 'volatility.dlllist' && rows) {
    return <DllListView rows={rows as DllRow[]} />
  }
  if (artifact.kind === 'volatility.filescan' && rows) {
    return (
      <FileScanView
        rows={rows as FileScanRow[]}
        onExtract={onExtract}
        extractingOffsets={extractingOffsets}
        extractedOffsets={extractedOffsets}
        failedOffsets={failedOffsets}
      />
    )
  }
  if (artifact.kind === 'volatility.registry.hivelist' && rows) {
    return <HiveListView rows={rows as HiveListRow[]} />
  }
  if (artifact.kind === 'volatility.malfind' && rows) {
    return <MalfindView rows={rows as MalfindRow[]} />
  }
  // volatility.cmdline's real row shape ({PID, Process, Args}) already
  // renders adequately through the generic fallback below -- no dedicated
  // component needed (verified against real captured rows,
  // poc/volatility_multiplugin/output.txt).
  return <GenericArtifactView content={artifact.content} />
}
