import { RiskMeter } from "@/components/RiskMeter";
import { StageBadge } from "@/components/StageBadge";
import { DegradedBanner } from "@/components/DegradedBanner";
import { EvidencePanel } from "@/components/EvidencePanel";
import { ObservedForecastLegend } from "@/components/ObservedForecastLegend";
import { FlowTable } from "@/components/FlowTable";

export default function OverviewPage() {
  return (
    <main className="p-6 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <header className="flex items-baseline justify-between">
        <div>
          <h1 className="text-display text-ink tracking-tight">
            SENTINEL
          </h1>
          <p className="text-body text-ink-muted mt-1">
            Network Threat Intelligence — Overview
          </p>
        </div>
        <ObservedForecastLegend />
      </header>

      {/* Risk trajectory section */}
      <section className="bg-canvas-panel border border-structure-hairline rounded-lg p-6">
        <h2 className="text-section text-ink mb-4">
          Risk Trajectory
        </h2>
        <div className="space-y-4">
          <RiskMeter probability={0.72} uncertainty={[0.65, 0.81]} method="world-model-rssm-v1" />
          <RiskMeter probability={0.34} size="sm" method="baseline-v3" />
          <RiskMeter probability={0.91} size="lg" method="world-model-rssm-v1" />
        </div>
      </section>

      {/* Active threats */}
      <section className="bg-canvas-panel border border-structure-hairline rounded-lg p-6">
        <h2 className="text-section text-ink mb-4">
          Active Threats
        </h2>
        <div className="space-y-3">
          <StageBadge
            stage="lateral-movement"
            technique="T1021.002"
            confidence={0.87}
            method="world-model-rssm-v1"
          />
          <StageBadge
            stage="reconnaissance"
            technique="T1046"
            confidence={0.94}
            method="rule-detector"
          />
          <StageBadge
            stage="exfiltration"
            technique="T1041"
            confidence={0.68}
            method="hybrid"
          />
        </div>
      </section>

      {/* Degraded mode */}
      <section className="space-y-3">
        <h2 className="text-section text-ink">
          System Status
        </h2>
        <DegradedBanner
          severity="warning"
          component="Inference Worker"
          reason="World model unavailable — falling back to rule detectors"
        />
        <DegradedBanner
          severity="info"
          component="Event Bus"
          reason="Sampling at 1:2 — detection sensitivity reduced"
        />
      </section>

      {/* Evidence */}
      <section className="bg-canvas-panel border border-structure-hairline rounded-lg p-6">
        <h2 className="text-section text-ink mb-4">
          Explanation — 192.168.10.8
        </h2>
        <EvidencePanel
          items={[
            { feature: "dst_port_nunique", value: 47, attribution: 0.312, method: "SHAP-exact-linear", description: "Distinct destination ports" },
            { feature: "flag_syn_ratio", value: 0.94, attribution: 0.218, method: "SHAP-exact-linear", description: "SYN flag ratio" },
            { feature: "iat_variance", value: 0.0023, attribution: 0.112, method: "SHAP-exact-linear", description: "Inter-arrival time variance" },
            { feature: "bytes_out_total", value: 1_247_000, attribution: 0.089, method: "SHAP-exact-linear", description: "Total outbound bytes" },
          ]}
        />
      </section>

      {/* Flow table */}
      <section className="bg-canvas-panel border border-structure-hairline rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-structure-hairline">
          <h2 className="text-section text-ink">
            Recent Flows
          </h2>
        </div>
        <FlowTable
          rows={[
            { id: "1", timestamp: "14:19:03", src: "192.168.10.8", dst: "10.0.0.15", sport: 49152, dport: 22, proto: "TCP", bytes: 1247, packets: 8, flags: "SYN", risk: 0.72, stage: "lateral-movement" },
            { id: "2", timestamp: "14:19:03", src: "192.168.10.8", dst: "10.0.0.20", sport: 49153, dport: 445, proto: "TCP", bytes: 892, packets: 5, flags: "SYN,ACK", risk: 0.81, stage: "lateral-movement" },
            { id: "3", timestamp: "14:19:04", src: "10.0.0.5", dst: "8.8.8.8", sport: 51234, dport: 53, proto: "UDP", bytes: 64, packets: 1, flags: "", risk: 0.08 },
            { id: "4", timestamp: "14:19:04", src: "192.168.10.8", dst: "10.0.0.25", sport: 49154, dport: 3389, proto: "TCP", bytes: 2048, packets: 12, flags: "PSH,ACK", risk: 0.91, stage: "credential-access" },
          ]}
        />
      </section>
    </main>
  );
}
