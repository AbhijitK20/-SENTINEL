"use client";

import { cn } from "@/lib/utils";

/**
 * StageBadge — MITRE tactic + technique, with confidence and evidence.
 *
 * §4.1 rule 4: "Every number names its method."
 * The method label is always visible, reachable in one interaction.
 */

type Stage =
  | "reconnaissance"
  | "initial-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "defense-evasion"
  | "credential-access"
  | "lateral-movement"
  | "collection"
  | "exfiltration"
  | "command-and-control"
  | "impact"
  | "unknown";

const STAGE_COLORS: Record<Stage, string> = {
  reconnaissance:       "bg-risk-quiet/20 text-risk-quiet border-risk-quiet/30",
  "initial-access":     "bg-risk-elevated/20 text-risk-elevated border-risk-elevated/30",
  execution:            "bg-risk-elevated/20 text-risk-elevated border-risk-elevated/30",
  persistence:          "bg-risk-concerning/20 text-risk-concerning border-risk-concerning/30",
  "privilege-escalation":"bg-risk-concerning/20 text-risk-concerning border-risk-concerning/30",
  "defense-evasion":    "bg-risk-concerning/20 text-risk-concerning border-risk-concerning/30",
  "credential-access":  "bg-risk-critical/20 text-risk-critical border-risk-critical/30",
  "lateral-movement":   "bg-risk-critical/20 text-risk-critical border-risk-critical/30",
  collection:           "bg-risk-critical/20 text-risk-critical border-risk-critical/30",
  exfiltration:         "bg-risk-severe/20 text-risk-severe border-risk-severe/30",
  "command-and-control":"bg-risk-severe/20 text-risk-severe border-risk-severe/30",
  impact:               "bg-risk-severe/20 text-risk-severe border-risk-severe/30",
  unknown:              "bg-canvas-raised text-ink-muted border-structure-hairline",
};

const STAGE_ABBREVIATIONS: Record<Stage, string> = {
  reconnaissance:       "TA0043",
  "initial-access":     "TA0001",
  execution:            "TA0002",
  persistence:          "TA0003",
  "privilege-escalation":"TA0004",
  "defense-evasion":    "TA0005",
  "credential-access":  "TA0006",
  "lateral-movement":   "TA0008",
  collection:           "TA0009",
  exfiltration:         "TA0010",
  "command-and-control":"TA0011",
  impact:               "TA0040",
  unknown:              "N/A",
};

interface StageBadgeProps {
  stage: Stage;
  technique?: string;
  confidence?: number;
  method?: string;
  className?: string;
}

export function StageBadge({
  stage,
  technique,
  confidence,
  method,
  className,
}: StageBadgeProps) {
  const colors = STAGE_COLORS[stage] ?? STAGE_COLORS.unknown;
  const tacticId = STAGE_ABBREVIATIONS[stage] ?? "N/A";

  return (
    <div className={cn("inline-flex items-center gap-2", className)}>
      <span
        className={cn(
          "inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm text-label font-medium border",
          colors,
        )}
      >
        <span className="font-mono text-micro opacity-70">{tacticId}</span>
        <span className="capitalize">{stage.replace(/-/g, " ")}</span>
      </span>

      {technique && (
        <span className="text-mono text-micro text-ink-muted">
          {technique}
        </span>
      )}

      {confidence !== undefined && (
        <span className="text-mono text-micro text-ink-muted">
          {Math.round(confidence * 100)}%
        </span>
      )}

      {method && (
        <span className="text-micro text-ink-muted/60">
          via {method}
        </span>
      )}
    </div>
  );
}
