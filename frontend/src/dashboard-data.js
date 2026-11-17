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

export function prependUnique(items, item, key, limit = 20) {
  if (!item || !item[key]) return items;
  return [item, ...items.filter((existing) => existing[key] !== item[key])].slice(0, limit);
}

export function getIncidentDashboardData(page, stats) {
  return {
    incidents: (page?.items || []).map((incident) => ({
      id: incident.incident_id,
      sourceIp: incident.source_ip,
      status: incident.status,
      severity: incident.severity,
      confidence: incident.confidence,
      rules: incident.detection_rules || [],
      evidence: incident.evidence_summary || [],
      sensors: incident.contributing_sensors || [],
      lastSeen: incident.last_seen,
    })),
    total: Number.isInteger(page?.total) ? page.total : 0,
    statusCounts: {
      open: stats?.open ?? 0,
      acknowledged: stats?.acknowledged ?? 0,
      resolved: stats?.resolved ?? 0,
    },
    severityCounts: stats?.severity_counts || {},
  };
}

export function getCowrieDashboardData(events) {
  const rows = Array.isArray(events) ? events : [];
  return {
    records: rows.map((event) => ({
      id: event.event_id,
      type: event.event_type,
      sourceIp: event.source_ip || "Address unavailable",
      timestamp: event.timestamp,
      summary: event.summary,
      sessionRef: event.session_ref || "Unavailable",
      authOutcome: event.authentication_outcome,
      commandAttempt: event.command_attempt === true,
    })),
    authenticationFailures: rows.filter((event) => event.authentication_outcome === "failed").length,
    authenticationSuccesses: rows.filter((event) => event.authentication_outcome === "success").length,
    sessionEvents: rows.filter((event) => ["cowrie_session_connected", "cowrie_session_closed"].includes(event.event_type)).length,
    commandAttempts: rows.filter((event) => event.command_attempt === true).length,
  };
}

export function getProfileDashboardData(profiles, stats, recommendations) {
  const rows = Array.isArray(profiles) ? profiles : [];
  const categoryCounts = stats?.category_counts && typeof stats.category_counts === "object"
    ? stats.category_counts
    : {};
  const clusterCounts = stats?.cluster_counts && typeof stats.cluster_counts === "object"
    ? stats.cluster_counts
    : {};
  return {
    profiles: rows.map((profile) => ({
      id: profile.profile_id,
      sourceRef: profile.source_ref,
      firstObserved: profile.first_observed,
      lastObserved: profile.last_observed,
      observations: profile.observation_count,
      category: profile.classification,
      anomalyIndex: Number.isFinite(profile.anomaly_index) ? profile.anomaly_index : null,
      cluster: Number.isInteger(profile.cluster) ? profile.cluster : null,
      modelVersion: profile.model_version,
      features: profile.features || {},
      influentialFeatures: profile.influential_features || {},
      history: profile.history || [],
      limitations: profile.limitations || [],
    })),
    categoryCounts,
    clusterCounts,
    meanAnomalyIndex: Number.isFinite(stats?.mean_anomaly_index) ? stats.mean_anomaly_index : null,
    totalProfiles: Number.isInteger(stats?.total_profiles) ? stats.total_profiles : rows.length,
    modelVersion: stats?.model_version || rows[0]?.model_version || null,
    recommendations: (Array.isArray(recommendations) ? recommendations : []).map((item) => ({
      id: item.recommendation_id,
      profileId: item.profile_id,
      category: item.profile_category,
      strategy: item.proposed_strategy,
      action: item.action,
      title: item.title,
      rationale: item.rationale,
      supportingFeatures: item.supporting_features || {},
      expectedScenario: item.expected_scenario,
      status: item.status,
      evaluation: item.evaluation || null,
      riskConstraints: item.risk_constraints || [],
    })),
  };
}

export function getExperimentDashboardData(experiment) {
  if (!experiment) return { modeRows: [], comparisonRows: [], scenarioRows: [], adaptationRows: [] };
  return {
    modeRows: (experiment.mode_metrics || []).map((mode) => ({
      mode: mode.mode,
      coverage: mode.detection_coverage,
      capture: mode.event_capture_rate,
      incidentRate: mode.incident_detection_rate,
      falsePositive: mode.false_positive_rate,
      falseNegative: mode.false_negative_rate,
      completion: mode.scenario_completion_rate,
      processingMs: mode.average_event_processing_ms,
      adaptations: mode.adaptations_applied,
      meanReward: mode.mean_strategy_reward,
      simulatedEngagement: mode.simulated_engagement_rate,
      meanSyntheticDepth: mode.mean_synthetic_interaction_depth,
      medianSyntheticDuration: mode.median_synthetic_session_duration_seconds,
      uniqueDecoysAccessed: mode.unique_decoys_accessed,
      strategyCounts: mode.strategy_selection_counts || {},
      reactionCounts: mode.attacker_reaction_counts || {},
    })),
    comparisonRows: experiment.comparison?.metrics || [],
    scenarioRows: experiment.scenario_results || [],
    adaptationRows: (experiment.scenario_results || []).filter((row) => row.mode !== "baseline" && row.adaptation_reason),
  };
}
