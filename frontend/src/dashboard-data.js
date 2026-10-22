export function formatPercent(value) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : "Unavailable";
}

export function formatLatency(value) {
  return Number.isFinite(value) ? `${value.toFixed(2)} ms` : "Unavailable";
}

export function formatRatio(actual, total) {
  if (!Number.isFinite(actual) || !Number.isFinite(total)) return "Unavailable";
  return `${actual.toLocaleString()} / ${total.toLocaleString()}`;
}

export function scenarioShortName(name) {
  const names = {
    reconnaissance: "Recon",
    credential_probing: "Credentials",
    database_probing: "Database",
    multi_stage: "Multi-stage",
    repeated_access: "Repeated",
  };
  return names[name] || name;
}

export function getScenarioMetricRows(evaluation) {
  return (evaluation?.scenarios || []).map((scenario) => ({
    name: scenario.scenario,
    label: scenarioShortName(scenario.scenario),
    completionRate: scenario.completion_rate,
    eventRecordingRate: scenario.event_recording_rate,
    strategyChangeRate: scenario.strategy_change_rate,
    decoysGenerated: scenario.decoys_generated,
    medianLatencyMs: scenario.median_latency_ms,
    completedRuns: scenario.completed_runs,
    runsRequested: scenario.runs_requested,
    interactionsRecorded: scenario.interactions_recorded,
    interactionsAttempted: scenario.interactions_attempted,
    errors: scenario.errors,
  }));
}

export function getStrategyTimeline(evaluation) {
  return (evaluation?.runs || [])
    .filter((run) => run.simulation_summary?.observed_strategies?.length)
    .map((run) => ({
      id: run.simulation_id,
      scenario: run.scenario,
      repetition: run.repetition,
      strategies: run.simulation_summary.observed_strategies,
      generatedDecoyIds: run.simulation_summary.generated_decoy_ids || [],
      generatedCount: run.simulation_summary.decoys_generated,
    }));
}
