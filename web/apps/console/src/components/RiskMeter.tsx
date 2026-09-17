"use client";

import { cn } from "@/lib/utils";

/**
 * RiskMeter — probability with uncertainty band and an explicit numeral.
 *
 * The single most important visual element. Maps P(infiltration) to the
 * perceptually uniform risk ramp. Colour is never the sole carrier —
 * the numeral and bar height double-encode the value.
 *
 * §4.2: "Colour is never the only carrier. Verify with a greyscale
 * screenshot — if the greyscale version is unreadable, the design is wrong."
 */

type RiskLevel = "quiet" | "elevated" | "concerning" | "critical" | "severe";

function riskLevel(p: number): RiskLevel {
  if (p < 0.25) return "quiet";
  if (p < 0.50) return "elevated";
  if (p < 0.75) return "concerning";
  if (p < 0.90) return "critical";
  return "severe";
}

const RISK_COLORS: Record<RiskLevel, string> = {
  quiet:     "bg-risk-quiet",
  elevated:  "bg-risk-elevated",
  concerning:"bg-risk-concerning",
  critical:  "bg-risk-critical",
  severe:    "bg-risk-severe",
};

const RISK_TEXT: Record<RiskLevel, string> = {
  quiet:     "text-risk-quiet",
  elevated:  "text-risk-elevated",
  concerning:"text-risk-concerning",
  critical:  "text-risk-critical",
  severe:    "text-risk-severe",
};

const RISK_LABELS: Record<RiskLevel, string> = {
  quiet:     "Quiet",
  elevated:  "Elevated",
  concerning:"Concerning",
  critical:  "Critical",
  severe:    "Severe",
};

interface RiskMeterProps {
  probability: number;
  uncertainty?: [number, number]; // [lower, upper] bounds
  method?: string;
  label?: string;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  className?: string;
}

export function RiskMeter({
  probability,
  uncertainty,
  method,
  label,
  size = "md",
  showLabel = true,
  className,
}: RiskMeterProps) {
  const level = riskLevel(probability);
  const pct = Math.round(probability * 100);

  const heights = { sm: "h-1.5", md: "h-2.5", lg: "h-4" };
  const textSizes = { sm: "text-data", md: "text-body", lg: "text-section" };

  return (
    <div className={cn("flex flex-col gap-1", className)}>
      <div className="flex items-baseline gap-2">
        <span className={cn("font-mono font-bold tabular-nums", textSizes[size], RISK_TEXT[level])}>
          {pct}%
        </span>
        {showLabel && (
          <span className="text-label text-ink-muted uppercase tracking-wide">
            {label ?? RISK_LABELS[level]}
          </span>
        )}
      </div>

      <div className={cn("w-full rounded-sm bg-canvas-raised overflow-hidden relative", heights[size])}>
        {/* Main bar */}
        <div
          className={cn("absolute inset-y-0 left-0 rounded-sm transition-all duration-normal", RISK_COLORS[level])}
          style={{ width: `${pct}%` }}
        />

        {/* Uncertainty band */}
        {uncertainty && (
          <div
            className="absolute inset-y-0 bg-white/10 rounded-sm"
            style={{
              left: `${uncertainty[0] * 100}%`,
              width: `${(uncertainty[1] - uncertainty[0]) * 100}%`,
            }}
          />
        )}
      </div>

      {method && (
        <span className="text-micro text-ink-muted font-mono">
          {method}
        </span>
      )}
    </div>
  );
}
