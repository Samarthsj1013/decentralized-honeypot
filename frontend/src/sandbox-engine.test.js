import test from "node:test";
import assert from "node:assert/strict";
import {
  compareSandboxStrategies,
  createEmptySandboxState,
  evaluateSandboxRecommendation,
  filterSandboxEvents,
  normalizeIntegerInput,
  publishSandboxIndicator,
  resetSandboxState,
  reviewSandboxIndicator,
  runSandboxSimulation,
  runSandboxSimulationAsync,
  SANDBOX_SCENARIOS,
  validateSandboxBundle,
  validateSandboxInput,
} from "./sandbox-engine.js";

const settings = (overrides = {}) => ({
  scenario: "multi_stage", interactionCount: 8, intensity: "medium", strategy: "adaptive", seed: 1842, ...overrides,
});

test("scenario inputs are allowlisted, strict, and bounded", () => {
  assert.equal(SANDBOX_SCENARIOS.length, 7);
  assert.throws(() => validateSandboxInput(settings({ scenario: "https://example.com" })), /supported synthetic scenario/);
  assert.throws(() => validateSandboxInput(settings({ interactionCount: 25 })), /between 1 and 24/);
  assert.throws(() => validateSandboxInput(settings({ interactionCount: 0 })), /between 1 and 24/);
  assert.throws(() => validateSandboxInput(settings({ seed: -1 })), /Seed must be an integer/);
  assert.throws(() => validateSandboxInput({ ...settings(), payload: "arbitrary" }), /unsupported field/);
});

test("valid integer inputs drop leading zeros without accepting invalid values", () => {
  assert.equal(normalizeIntegerInput("024", 1, 24), "24");
  assert.equal(normalizeIntegerInput("0007", 1, 24), "7");
  assert.equal(normalizeIntegerInput("000", 1, 24), null);
  assert.equal(normalizeIntegerInput("25", 1, 24), null);
  assert.equal(normalizeIntegerInput("2.4", 1, 24), null);
  assert.equal(normalizeIntegerInput("", 1, 24), null);
});

test("seeded execution is deterministic for equivalent run identity and clock", () => {
  const options = { runId: "test-run", startedAt: "2026-11-26T10:00:00.000Z" };
  assert.deepEqual(runSandboxSimulation(settings(), options), runSandboxSimulation(settings(), options));
  assert.equal(runSandboxSimulation(settings(), options).recorded, 8);
  const mixedA = runSandboxSimulation(settings({ scenario: "mixed_activity", interactionCount: 24, seed: 1 }), { runId: "mixed-a" });
  const mixedB = runSandboxSimulation(settings({ scenario: "mixed_activity", interactionCount: 24, seed: 2 }), { runId: "mixed-b" });
  assert.notDeepEqual(mixedA.events.map((event) => event.eventType), mixedB.events.map((event) => event.eventType));
});

test("scenario, interaction count, and intensity affect generated telemetry", () => {
  const reconnaissance = runSandboxSimulation(settings({ scenario: "service_reconnaissance", interactionCount: 5 }), { runId: "recon" });
  const benign = runSandboxSimulation(settings({ scenario: "benign_activity", interactionCount: 5 }), { runId: "benign" });
  const more = runSandboxSimulation(settings({ scenario: "ssh_authentication_probing", interactionCount: 11 }), { runId: "more" });
  assert.ok(reconnaissance.events.every((event) => event.eventType === "service_observed"));
  assert.ok(benign.events.every((event) => event.suspicious === false));
  assert.equal(more.recorded, 11);
  assert.equal(more.alerts[0].rule, "repeated_authentication_failures");
  const high = runSandboxSimulation(settings({ scenario: "benign_activity", intensity: "high" }), { runId: "fast" });
  assert.equal(high.alerts.length, 0);
  assert.equal(high.recommendations.length, 0);
  assert.equal(high.falsePositiveRate, 0);
});

test("rule alerts and incidents are derived from event evidence", () => {
  const result = runSandboxSimulation(settings({ scenario: "multi_stage", interactionCount: 9 }), { runId: "stages" });
  assert.ok(result.alerts.some((alert) => alert.rule === "repeated_authentication_failures"));
  assert.ok(result.alerts.some((alert) => alert.rule === "repeated_decoy_interaction"));
  assert.ok(result.alerts.some((alert) => alert.rule === "cross_source_synthetic_correlation"));
  assert.equal(result.incidents.length, 1);
  assert.ok(result.incidents[0].eventIds.length > 1);
  assert.ok(result.incidents[0].rules.every((rule) => result.alerts.some((alert) => alert.rule === rule)));
});

test("benign control never triggers suspicious-activity rules or recommendations", () => {
  for (const intensity of ["low", "medium", "high"]) {
    const benign = runSandboxSimulation(settings({ scenario: "benign_activity", interactionCount: 24, intensity }), { runId: `benign-${intensity}` });
    assert.ok(benign.events.every((event) => event.suspicious === false));
    assert.equal(benign.alerts.length, 0);
    assert.equal(benign.incidents.length, 0);
    assert.equal(benign.recommendations.length, 0);
    assert.equal(benign.falsePositiveEvents, 0);
    assert.equal(benign.falsePositiveRate, 0);
  }
});

test("event filters apply event type, severity, and ordering without mutating source", () => {
  const run = runSandboxSimulation(settings({ scenario: "multi_stage", interactionCount: 9 }), { runId: "filter-test" });
  const originalOrder = run.events.map((event) => event.id);
  const filtered = filterSandboxEvents(run.events, { eventType: "authentication_failed", severity: "medium", sortOrder: "newest" });
  assert.ok(filtered.length > 0);
  assert.ok(filtered.every((event) => event.eventType === "authentication_failed" && event.severity === "medium"));
  assert.deepEqual(filtered.map((event) => event.timestamp), [...filtered.map((event) => event.timestamp)].sort().reverse());
  assert.deepEqual(run.events.map((event) => event.id), originalOrder);
});

test("behavior profile and recommendation features are transparent and observation-based", () => {
  const credential = runSandboxSimulation(settings({ scenario: "credential_decoy" }), { runId: "credential" });
  const benign = runSandboxSimulation(settings({ scenario: "benign_activity" }), { runId: "benign" });
  assert.equal(credential.profile.classification, "authentication probing");
  assert.equal(credential.profile.features.authenticationFailures, 0);
  assert.equal(credential.profile.features.authenticationAttempts, 8);
  assert.equal(credential.profile.features.decoyInteractions, 8);
  assert.equal(credential.recommendations[0].category, "authentication_decoys");
  assert.match(credential.profile.assessment, /heuristic; not the trained profile model/);
  assert.equal(benign.profile.classification, "benign control activity");
  assert.equal(benign.recommendations.length, 0);
});

test("static and adaptive runs generate disabled synthetic decoys from observed activity", () => {
  const adaptive = runSandboxSimulation(settings(), { runId: "adaptive" });
  const staticRun = runSandboxSimulation(settings({ strategy: "static" }), { runId: "static" });
  assert.ok(adaptive.decoyCoverage > staticRun.decoyCoverage);
  assert.ok(adaptive.syntheticDecoys.every((decoy) => decoy.syntheticOnly && decoy.enabled === false));
  assert.equal(adaptive.bundleValidation.valid, true);
  assert.equal(adaptive.bundleValidationFailures, 0);
  const tampered = { schemaVersion: 1, syntheticOnly: true, decoys: [{ id: "adaptive-decoy-file-decoy", category: "credential", syntheticOnly: true, enabled: false, payload: "no" }] };
  assert.equal(validateSandboxBundle(tampered, "adaptive").valid, false);
  assert.ok(validateSandboxBundle(tampered, "adaptive").issues.length >= 2);
});

test("evaluation replays the measured run and rejects recommendations without supporting evidence", () => {
  const run = runSandboxSimulation(settings({ scenario: "credential_decoy" }), { runId: "evaluation" });
  const outcome = evaluateSandboxRecommendation(run, run.recommendations[0]);
  assert.equal(outcome.outcome, "passed");
  assert.equal(outcome.interactionsAttempted, 8);
  assert.equal(outcome.interactionsRecorded, 8);
  assert.equal(outcome.bundleValidationFailures, 0);
  assert.throws(() => evaluateSandboxRecommendation(run, { id: "other" }), /belong to the current sandbox run/);
  const incompleteRun = { ...run, completion: "incomplete", recorded: 3 };
  const rejected = evaluateSandboxRecommendation(incompleteRun, run.recommendations[0]);
  assert.equal(rejected.outcome, "failed");
  assert.equal(rejected.interactionsRecorded, 3);
});

test("paired comparison uses identical scenario seeds and does not force adaptive superiority", () => {
  const output = compareSandboxStrategies(settings({ scenario: "benign_activity" }), 3);
  assert.equal(output.runs.length, 6);
  for (let index = 0; index < output.runs.length; index += 2) {
    assert.equal(output.runs[index].seed, output.runs[index + 1].seed);
    assert.equal(output.runs[index].recorded, output.runs[index + 1].recorded);
    assert.equal(output.runs[index].decoyCoverage, output.runs[index + 1].decoyCoverage);
  }
  assert.equal(output.static.falsePositiveRate, 0);
  assert.equal(output.adaptive.falsePositiveRate, 0);
  assert.throws(() => compareSandboxStrategies(settings(), 6), /between 1 and 5/);
});

test("simulated intelligence exchange validates allowlisted records, deduplicates, and requires explicit review", () => {
  const run = runSandboxSimulation(settings({ scenario: "ssh_authentication_probing" }), { runId: "exchange" });
  const alert = run.alerts[0];
  const first = publishSandboxIndicator(createEmptySandboxState().exchange, run, alert);
  assert.equal(first.received[0].status, "pending_review");
  assert.equal(first.received[0].origin, "Simulated Node A");
  const duplicate = publishSandboxIndicator(first, run, alert);
  assert.equal(duplicate.received.length, 1);
  assert.equal(duplicate.history.at(-1).status, "duplicate_ignored");
  const approved = reviewSandboxIndicator(first, first.received[0].indicator, "approved");
  assert.equal(approved.received[0].status, "approved");
  assert.throws(() => reviewSandboxIndicator(approved, first.received[0].indicator, "rejected"), /pending received indicator/);
});

test("async run reports real per-event progress and tab state is isolated and resettable", async () => {
  const progress = [];
  const run = await runSandboxSimulationAsync(settings({ interactionCount: 3 }), { runId: "progress", onProgress: (done) => progress.push(done) });
  assert.deepEqual(progress, [1, 2, 3]);
  assert.equal(run.recorded, 3);
  const firstTab = createEmptySandboxState();
  const secondTab = createEmptySandboxState();
  firstTab.run = run;
  firstTab.comparison = { stale: true };
  firstTab.evaluations = { stale: true };
  firstTab.reviewStates = { stale: true };
  firstTab.exchange.history.push({ action: "test" });
  assert.equal(secondTab.exchange.history.length, 0);
  const reset = resetSandboxState();
  assert.equal(reset.run, null);
  assert.equal(reset.comparison, null);
  assert.deepEqual(reset.evaluations, {});
  assert.deepEqual(reset.reviewStates, {});
  assert.deepEqual(reset.exchange, { received: [], history: [] });
});
