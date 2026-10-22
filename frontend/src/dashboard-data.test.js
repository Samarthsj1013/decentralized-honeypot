import test from "node:test";
import assert from "node:assert/strict";
import {
  formatLatency,
  formatPercent,
  formatRatio,
  getScenarioMetricRows,
  getStrategyTimeline,
} from "./dashboard-data.js";

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
