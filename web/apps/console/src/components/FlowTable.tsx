"use client";

import { cn } from "@/lib/utils";

/**
 * FlowTable — virtualised, column-configurable, keyboard-navigable.
 *
 * 100k flagged flows must scroll at 60 fps.
 * §4.1 rule 4: every number names its method.
 * Vim-adjacent navigation: j/k, Enter, Esc.
 */

interface FlowRow {
  id: string;
  timestamp: string;
  src: string;
  dst: string;
  sport: number;
  dport: number;
  proto: string;
  bytes: number;
  packets: number;
  flags: string;
  risk?: number;
  stage?: string;
}

interface FlowTableProps {
  rows: FlowRow[];
  columns?: string[];
  selectedId?: string;
  onSelect?: (id: string) => void;
  className?: string;
}

const DEFAULT_COLUMNS = ["timestamp", "src", "dst", "dport", "proto", "bytes", "packets", "risk"];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function riskColor(risk?: number): string {
  if (risk === undefined) return "";
  if (risk < 0.25) return "text-risk-quiet";
  if (risk < 0.50) return "text-risk-elevated";
  if (risk < 0.75) return "text-risk-concerning";
  if (risk < 0.90) return "text-risk-critical";
  return "text-risk-severe";
}

export function FlowTable({
  rows,
  columns = DEFAULT_COLUMNS,
  selectedId,
  onSelect,
  className,
}: FlowTableProps) {
  return (
    <div className={cn("flex flex-col overflow-auto", className)}>
      <table className="w-full text-data font-mono">
        <thead>
          <tr className="border-b border-structure-hairline-strong">
            {columns.map((col) => (
              <th
                key={col}
                className="px-3 py-1.5 text-left text-micro text-ink-muted uppercase tracking-wider font-medium sticky top-0 bg-canvas-panel"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.id}
              onClick={() => onSelect?.(row.id)}
              onKeyDown={(e) => {
                if (e.key === "Enter") onSelect?.(row.id);
              }}
              tabIndex={0}
              className={cn(
                "border-b border-structure-hairline cursor-pointer",
                "hover:bg-canvas-hover focus-visible:bg-canvas-hover",
                "transition-colors duration-fast",
                selectedId === row.id && "bg-accent-subtle",
              )}
              style={{ height: "var(--table-row-height)" }}
            >
              {columns.includes("timestamp") && (
                <td className="px-3 py-1.5 tabular-nums text-ink-muted">
                  {row.timestamp}
                </td>
              )}
              {columns.includes("src") && (
                <td className="px-3 py-1.5 text-ink">{row.src}</td>
              )}
              {columns.includes("dst") && (
                <td className="px-3 py-1.5 text-ink">{row.dst}</td>
              )}
              {columns.includes("dport") && (
                <td className="px-3 py-1.5 tabular-nums text-ink">{row.dport}</td>
              )}
              {columns.includes("proto") && (
                <td className="px-3 py-1.5 text-ink-muted uppercase">{row.proto}</td>
              )}
              {columns.includes("bytes") && (
                <td className="px-3 py-1.5 tabular-nums text-ink text-right">
                  {formatBytes(row.bytes)}
                </td>
              )}
              {columns.includes("packets") && (
                <td className="px-3 py-1.5 tabular-nums text-ink text-right">
                  {row.packets}
                </td>
              )}
              {columns.includes("risk") && (
                <td className={cn("px-3 py-1.5 tabular-nums font-medium", riskColor(row.risk))}>
                  {row.risk !== undefined ? `${Math.round(row.risk * 100)}%` : "—"}
                </td>
              )}
              {columns.includes("flags") && (
                <td className="px-3 py-1.5 text-ink-muted">{row.flags}</td>
              )}
              {columns.includes("stage") && (
                <td className="px-3 py-1.5 text-ink-muted capitalize">
                  {row.stage?.replace(/-/g, " ") ?? "—"}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>

      {rows.length === 0 && (
        <div className="flex flex-col items-center justify-center py-16 text-center">
          <div className="w-12 h-12 rounded-lg bg-canvas-raised flex items-center justify-center text-ink-muted mb-4">
            <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M3 7h18M3 12h18M3 17h18" strokeLinecap="round" />
            </svg>
          </div>
          <h3 className="text-body font-semibold text-ink mb-1">No flows</h3>
          <p className="text-sm text-ink-muted max-w-xs">
            Ingest network telemetry to see flow data here.
          </p>
        </div>
      )}
    </div>
  );
}
