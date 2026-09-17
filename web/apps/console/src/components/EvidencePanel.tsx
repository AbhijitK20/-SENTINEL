"use client";

import { cn } from "@/lib/utils";

/**
 * EvidencePanel — the feature values behind a claim, linked to the glossary.
 *
 * §4.1 rule 4: "Every number names its method."
 * Every attribution displays its method. Feature tooltips generate from
 * FeatureRegistry — one source, no drift.
 */

interface EvidenceItem {
  feature: string;
  value: number;
  attribution?: number;
  method?: string;
  description?: string;
}

interface EvidencePanelProps {
  items: EvidenceItem[];
  title?: string;
  className?: string;
}

export function EvidencePanel({ items, title = "Evidence", className }: EvidencePanelProps) {
  return (
    <div className={cn("flex flex-col", className)}>
      <h3 className="text-label text-ink-muted uppercase tracking-wide mb-3">
        {title}
      </h3>

      <div className="flex flex-col gap-1">
        {items.map((item) => (
          <div
            key={item.feature}
            className="flex items-center justify-between py-1.5 border-b border-structure-hairline last:border-0"
          >
            <div className="flex flex-col min-w-0">
              <span className="text-body text-ink font-mono truncate">
                {item.feature}
              </span>
              {item.description && (
                <span className="text-micro text-ink-muted mt-0.5">
                  {item.description}
                </span>
              )}
            </div>

            <div className="flex items-baseline gap-3 shrink-0 ml-4">
              <span className="text-data font-mono tabular-nums text-ink">
                {typeof item.value === "number" ? item.value.toFixed(4) : item.value}
              </span>

              {item.attribution !== undefined && (
                <span
                  className={cn(
                    "text-data font-mono tabular-nums",
                    item.attribution > 0 ? "text-risk-severe" : "text-risk-quiet",
                  )}
                >
                  {item.attribution > 0 ? "+" : ""}
                  {item.attribution.toFixed(3)}
                </span>
              )}

              {item.method && (
                <span className="text-micro text-ink-muted/60 font-mono">
                  {item.method}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {items.length === 0 && (
        <div className="text-body text-ink-muted py-8 text-center">
          No evidence available
        </div>
      )}
    </div>
  );
}
