"use client";

import { cn } from "@/lib/utils";

/**
 * DegradedBanner — the honest "we are running without X" surface.
 *
 * §4.1 rule 2: "Insufficient evidence is not low risk."
 * This component surfaces degradation explicitly. Never silently degrade.
 *
 * §5.4 backpressure policy:
 * - 80-100%: status indicator
 * - 100-150%: banner + API `degraded` flag
 * - >150%: banner + alert + audit record
 */

type DegradedSeverity = "info" | "warning" | "critical";

const SEVERITY_STYLES: Record<DegradedSeverity, string> = {
  info:     "bg-accent-subtle border-accent/30 text-ink",
  warning:  "bg-risk-concerning/10 border-risk-concerning/30 text-risk-concerning",
  critical: "bg-risk-severe/10 border-risk-severe/30 text-risk-severe",
};

interface DegradedBannerProps {
  severity: DegradedSeverity;
  reason: string;
  component?: string;
  action?: React.ReactNode;
  className?: string;
}

export function DegradedBanner({
  severity,
  reason,
  component,
  action,
  className,
}: DegradedBannerProps) {
  return (
    <div
      role="alert"
      className={cn(
        "flex items-center gap-3 px-4 py-2.5 border rounded-sm text-body",
        SEVERITY_STYLES[severity],
        className,
      )}
    >
      {/* Indicator dot */}
      <span
        className={cn(
          "w-2 h-2 rounded-full shrink-0",
          severity === "critical" && "bg-risk-severe animate-pulse-subtle",
          severity === "warning" && "bg-risk-concerning",
          severity === "info" && "bg-accent",
        )}
      />

      <div className="flex-1 min-w-0">
        <span className="font-medium">
          {component ? `${component}: ` : ""}
        </span>
        <span>{reason}</span>
      </div>

      {action && (
        <div className="shrink-0">{action}</div>
      )}
    </div>
  );
}
