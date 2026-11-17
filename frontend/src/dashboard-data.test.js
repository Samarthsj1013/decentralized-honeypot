import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  formatLatency,
  formatPercent,
  formatRatio,
  getScenarioMetricRows,
  getIncidentDashboardData,
  getCowrieDashboardData,
  getProfileDashboardData,
  getExperimentDashboardData,
  getStrategyTimeline,
  prependUnique,
} from "./dashboard-data.js";

test("browser source contains no configured reader or node bearer-token injection", () => {
  const here = new URL(".", import.meta.url);
  const apiSource = readFileSync(new URL("./api.js", here), "utf8");
  const envExample = readFileSync(new URL("../.env.example", here), "utf8");
  assert.doesNotMatch(apiSource, /VITE_API_READ_TOKEN|VITE_NETWORK_NODE_READ_TOKEN|Authorization:\s*`Bearer/);
  assert.doesNotMatch(envExample, /VITE_API_READ_TOKEN|VITE_NETWORK_NODE_READ_TOKEN/);
  assert.match(apiSource, /credentials:\s*"include"/);
  assert.match(apiSource, /X-CSRF-Token/);
});

test("missing measurements remain unavailable instead of becoming zero", () => {
  assert.equal(formatPercent(null), "Unavailable");
  assert.equal(formatLatency(null), "Unavailable");
  assert.equal(formatRatio(null, 4), "Unavailable");
});

test("scenario view model uses the evaluation API values", () => {
  const rows = getScenarioMetricRows({
    scenarios: [{
      scenario: "multi_stage",
      completion_rate: 0.75,
      event_recording_rate: 0.9,
      strategy_change_rate: null,
      decoys_generated: 4,
      median_latency_ms: 24.419,
      completed_runs: 3,
      runs_requested: 4,
      interactions_recorded: 9,
      interactions_attempted: 10,
      errors: 1,
    }],
  });
  assert.deepEqual(rows[0], {
    name: "multi_stage",
    label: "Multi-stage",
    completionRate: 0.75,
    eventRecordingRate: 0.9,
    strategyChangeRate: null,
    decoysGenerated: 4,
    medianLatencyMs: 24.419,
    completedRuns: 3,
    runsRequested: 4,
    interactionsRecorded: 9,
    interactionsAttempted: 10,
    errors: 1,
  });
});

test("strategy timeline includes only sequences returned by the API", () => {
  const timeline = getStrategyTimeline({
    runs: [
      {
        simulation_id: "run-a",
        scenario: "multi_stage",
        repetition: 1,
        simulation_summary: {
          observed_strategies: ["neutral_response", "credential_decoy"],
          generated_decoy_ids: ["generated-file-x"],
          decoys_generated: 1,
        },
      },
      {
        simulation_id: "run-b",
        scenario: "reconnaissance",
        repetition: 1,
        simulation_summary: { observed_strategies: null },
      },
    ],
  });
  assert.equal(timeline.length, 1);
  assert.deepEqual(timeline[0].strategies, ["neutral_response", "credential_decoy"]);
  assert.deepEqual(timeline[0].generatedDecoyIds, ["generated-file-x"]);
});

test("live updates are prepended, deduplicated, and bounded", () => {
  const existing = [{ event_id: "event-a" }, { event_id: "event-b" }];
  assert.deepEqual(
    prependUnique(existing, { event_id: "event-a", severity: "high" }, "event_id"),
    [{ event_id: "event-a", severity: "high" }, { event_id: "event-b" }],
  );
  assert.equal(prependUnique(existing, { event_id: "event-c" }, "event_id", 2).length, 2);
  assert.equal(prependUnique(existing, {}, "event_id"), existing);
});

test("incident dashboard transformation displays only API-provided incident data", () => {
  const view = getIncidentDashboardData({ total: 1, items: [{
    incident_id: "incident-1", source_ip: "192.0.2.4", status: "open",
    severity: "high", confidence: 0.8, detection_rules: ["repeated_zeek_connections"],
    evidence_summary: ["Three Zeek connections in the window."], contributing_sensors: ["zeek:sensor-a"],
    last_seen: "2026-11-06T10:00:00Z",
  }] }, { open: 1, acknowledged: 0, resolved: 2, severity_counts: { high: 1 } });
  assert.equal(view.total, 1);
  assert.equal(view.incidents[0].id, "incident-1");
  assert.deepEqual(view.statusCounts, { open: 1, acknowledged: 0, resolved: 2 });
  assert.deepEqual(view.severityCounts, { high: 1 });
  assert.deepEqual(getIncidentDashboardData(null, null).incidents, []);
});

test("Cowrie dashboard summarizes safe event fields without command or credential content", () => {
  const view = getCowrieDashboardData([
    { event_id: "c1", event_type: "cowrie_login_failed", authentication_outcome: "failed", source_ip: "192.0.2.7", timestamp: "2026-11-06T10:00:00Z", summary: "SSH authentication failed", session_ref: "abc", command_attempt: false },
    { event_id: "c2", event_type: "cowrie_command_attempt", source_ip: "192.0.2.7", timestamp: "2026-11-06T10:00:01Z", summary: "Command attempt observed; command text and output withheld", command_attempt: true },
  ]);
  assert.equal(view.authenticationFailures, 1);
  assert.equal(view.authenticationSuccesses, 0);
  assert.equal(view.commandAttempts, 1);
  assert.equal(view.records[1].sourceIp, "192.0.2.7");
  assert.equal(JSON.stringify(view).includes("password"), false);
  assert.deepEqual(getCowrieDashboardData(null).records, []);
});

test("profile dashboard preserves unavailable scores and maps recommendation review state", () => {
  const data = getProfileDashboardData(
    [{ profile_id: "profile-123", source_ref: "abc", classification: "authentication_probing", anomaly_index: null, cluster: 2, model_version: "attacker-profile-synthetic-v1", features: { failed_auth_count: 4 }, history: [], limitations: [] }],
    { total_profiles: 1, category_counts: { authentication_probing: 1 }, cluster_counts: { 2: 1 }, mean_anomaly_index: null, model_version: "attacker-profile-synthetic-v1" },
    [{ recommendation_id: "rec-1", profile_id: "profile-123", status: "pending", proposed_strategy: "credential_decoy", supporting_features: { failed_auth_count: 4 }, risk_constraints: ["synthetic only"] }],
  );
  assert.equal(data.totalProfiles, 1);
  assert.equal(data.profiles[0].anomalyIndex, null);
  assert.equal(data.profiles[0].features.failed_auth_count, 4);
  assert.equal(data.recommendations[0].status, "pending");
  assert.equal(data.recommendations[0].evaluation, null);
});

test("experiment dashboard renders measured comparison and adaptation records only", () => {
  const data = getExperimentDashboardData({
    mode_metrics: [{ mode: "baseline", detection_coverage: 0.5, event_capture_rate: 1, incident_detection_rate: 0.5, false_positive_rate: null, false_negative_rate: 0.5, scenario_completion_rate: 1, average_event_processing_ms: 0.2, adaptations_applied: 0, simulated_engagement_rate: 0.5, mean_synthetic_interaction_depth: 3, median_synthetic_session_duration_seconds: 5, unique_decoys_accessed: null }],
    comparison: { metrics: [{ metric: "detection_coverage", baseline: 0.5, adaptive: null, absolute_difference: null, percentage_difference: null }] },
    scenario_results: [{ scenario: "reconnaissance", mode: "adaptive", adaptation_reason: "selected synthetic strategy", true_positives: 2 }],
  });
  assert.equal(data.modeRows[0].coverage, 0.5);
  assert.equal(data.modeRows[0].falsePositive, null);
  assert.equal(data.modeRows[0].simulatedEngagement, 0.5);
  assert.equal(data.modeRows[0].meanSyntheticDepth, 3);
  assert.equal(data.modeRows[0].uniqueDecoysAccessed, null);
  assert.equal(data.comparisonRows[0].absolute_difference, null);
  assert.equal(data.adaptationRows.length, 1);
  assert.deepEqual(getExperimentDashboardData(null).scenarioRows, []);
});
