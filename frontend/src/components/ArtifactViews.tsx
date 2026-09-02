import { useState } from 'react'
import type { Artifact } from '../types'

/**
 * Gap Audit Milestone AAAAA: kind-aware rendering for StructuredArtifact
 * content, per the design conversation's "scenario 4" decision. `content`
 * is intentionally opaque (src/domain/artifact.py) -- these components
 * give the two real kinds this platform emits today (Volatility
 * `pstree`/`psscan`) real, curated shape; anything else falls back to a
 * generic table (or raw JSON if it isn't even row-shaped), so a future
 * module's new `kind` renders usably with zero new frontend code, not a
 * blank/broken view.
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

function formatCell(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
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
export function ArtifactContent({ artifact }: { artifact: Artifact }) {
  const rows = Array.isArray(artifact.content.rows)
    ? (artifact.content.rows as ProcessRow[])
    : null

  if (artifact.kind === 'volatility.pstree' && rows) {
    return <ProcessTreeView rows={rows} />
  }
  if (artifact.kind === 'volatility.psscan' && rows) {
    return <ProcessTableView rows={rows} />
  }
  return <GenericArtifactView content={artifact.content} />
}
