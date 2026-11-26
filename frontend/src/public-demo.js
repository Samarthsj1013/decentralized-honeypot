export const PUBLIC_DEMO_LABEL = "Placement Demonstration — Synthetic Security Data";

export function publicDemoMetrics(snapshot) {
  const overview = snapshot?.overview || {};
  return [
    { label: "Telemetry events", value: count(overview.telemetry_events), detail: "Curated synthetic sample" },
    { label: "Security alerts", value: count(overview.alerts), detail: "Rule examples, not live detections" },
    { label: "Incidents", value: count(overview.incidents), detail: "Synthetic correlation example" },
    { label: "Behavior profiles", value: count(overview.profiles), detail: "Synthetic model output" },
    { label: "Recommendations", value: count(overview.recommendations), detail: "Review workflow examples" },
  ];
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString() : "Unavailable";
}
