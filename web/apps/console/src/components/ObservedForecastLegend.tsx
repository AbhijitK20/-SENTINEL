"use client";

import { cn } from "@/lib/utils";

/**
 * ObservedForecastLegend — persistent, unmissable distinction.
 *
 * §4.1 rule 1: "Observed and forecast are never confusable."
 * Different line style, different colour family, explicit divider at "now",
 * and a persistent legend. Already a core principle; make it a visual law.
 */

interface ObservedForecastLegendProps {
  className?: string;
}

export function ObservedForecastLegend({ className }: ObservedForecastLegendProps) {
  return (
    <div className={cn("flex items-center gap-4 text-label", className)}>
      {/* Observed — solid line, confirmed colour */}
      <div className="flex items-center gap-1.5">
        <svg width="24" height="2" className="shrink-0">
          <line
            x1="0" y1="1" x2="24" y2="1"
            stroke="currentColor"
            strokeWidth="2"
            className="text-confirmed"
          />
        </svg>
        <span className="text-ink-secondary">Observed</span>
      </div>

      {/* Forecast — dashed line, risk-elevated colour */}
      <div className="flex items-center gap-1.5">
        <svg width="24" height="2" className="shrink-0">
          <line
            x1="0" y1="1" x2="24" y2="1"
            stroke="currentColor"
            strokeWidth="2"
            strokeDasharray="4 3"
            className="text-risk-elevated"
          />
        </svg>
        <span className="text-ink-secondary">Forecast</span>
      </div>

      {/* Uncertainty band */}
      <div className="flex items-center gap-1.5">
        <svg width="24" height="12" className="shrink-0">
          <rect
            x="0" y="0" width="24" height="12"
            fill="currentColor"
            className="text-risk-elevated/10"
            rx="2"
          />
        </svg>
        <span className="text-ink-secondary">Uncertainty</span>
      </div>

      {/* Threshold */}
      <div className="flex items-center gap-1.5">
        <svg width="24" height="2" className="shrink-0">
          <line
            x1="0" y1="1" x2="24" y2="1"
            stroke="currentColor"
            strokeWidth="1"
            strokeDasharray="2 2"
            className="text-risk-concerning"
          />
        </svg>
        <span className="text-ink-secondary">Threshold</span>
      </div>

      {/* Insufficient evidence */}
      <div className="flex items-center gap-1.5">
        <svg width="24" height="12" className="shrink-0">
          <rect
            x="0" y="0" width="24" height="12"
            className="hatch-insufficient"
            rx="2"
          />
        </svg>
        <span className="text-ink-secondary">Insufficient</span>
      </div>
    </div>
  );
}
