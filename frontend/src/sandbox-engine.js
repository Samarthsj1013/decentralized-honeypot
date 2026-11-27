const SCENARIOS = Object.freeze({
  ssh_authentication_probing: { label: "SSH authentication probing", sensor: "cowrie" },
  repeated_login_failures: { label: "Repeated login failures", sensor: "cowrie" },
  service_reconnaissance: { label: "Service reconnaissance", sensor: "zeek" },
  credential_decoy: { label: "Credential-decoy interaction", sensor: "cowrie" },
  multi_stage: { label: "Multi-stage synthetic activity", sensor: "mixed" },
  benign_activity: { label: "Benign control activity", sensor: "zeek" },
  mixed_activity: { label: "Mixed synthetic activity", sensor: "mixed" },
});

const INTENSITIES = Object.freeze({ low: 12, medium: 3, high: 0.5 });
const MAX_INTERACTIONS = 24;
export const MAX_SANDBOX_SEED = 0xffffffff;
const SERVICE_LABELS = ["ssh", "web", "database", "file-service", "api"];

export const SANDBOX_SCENARIOS = Object.entries(SCENARIOS).map(([value, item]) => ({ value, label: item.label }));
export const MAX_SANDBOX_INTERACTIONS = MAX_INTERACTIONS;

export function normalizeIntegerInput(value, minimum, maximum) {
  if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < minimum || number > maximum) return null;
  return String(number);
}

export function filterSandboxEvents(events, { eventType = "all", severity = "all", sortOrder = "newest" } = {}) {
  return events
    .filter((event) => eventType === "all" || event.eventType === eventType)
    .filter((event) => severity === "all" || event.severity === severity)
    .slice()
    .sort((left, right) => sortOrder === "newest"
      ? right.timestamp.localeCompare(left.timestamp)
      : left.timestamp.localeCompare(right.timestamp));
}

export function validateSandboxInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new TypeError("Simulation settings must be an object.");
  const allowed = new Set(["scenario", "interactionCount", "intensity", "strategy", "seed"]);
  if (Object.keys(input).some((key) => !allowed.has(key))) throw new TypeError("Simulation settings contain an unsupported field.");
  if (!Object.hasOwn(SCENARIOS, input.scenario)) throw new TypeError("Select a supported synthetic scenario.");
  if (!Number.isInteger(input.interactionCount) || input.interactionCount < 1 || input.interactionCount > MAX_INTERACTIONS) {
    throw new RangeError(`Interaction count must be between 1 and ${MAX_INTERACTIONS}.`);
  }
  if (!Object.hasOwn(INTENSITIES, input.intensity)) throw new TypeError("Select a supported simulation intensity.");
  if (!new Set(["static", "adaptive"]).has(input.strategy)) throw new TypeError("Select a static or adaptive strategy.");
  if (input.seed !== null && (!Number.isInteger(input.seed) || input.seed < 0 || input.seed > MAX_SANDBOX_SEED)) {
    throw new RangeError(`Seed must be an integer from 0 to ${MAX_SANDBOX_SEED}, or blank.`);
  }
  return Object.freeze({ ...input });
}

function seededRandom(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function activityFor(scenario, index, random, intensity) {
  if (scenario === "ssh_authentication_probing" || scenario === "repeated_login_failures") {
    return { eventType: "authentication_failed", action: "attempt_login", suspicious: true, severity: intensity === "high" ? "high" : "medium", sourceSystem: "cowrie", service: "ssh" };
  }
  if (scenario === "service_reconnaissance") {
    return { eventType: "service_observed", action: "inspect_service", suspicious: true, severity: "low", sourceSystem: "zeek", service: SERVICE_LABELS[index % SERVICE_LABELS.length] };
  }
  if (scenario === "credential_decoy") {
    return { eventType: "credential_decoy_interaction", action: "attempt_login", suspicious: true, severity: "medium", sourceSystem: "cowrie", service: "credential-decoy" };
  }
  if (scenario === "benign_activity") {
    return { eventType: "routine_connection", action: "read", suspicious: false, severity: "low", sourceSystem: "zeek", service: "web" };
  }
  if (scenario === "mixed_activity") {
    if (random() < (intensity === "high" ? 0.7 : 0.45)) {
      return { eventType: "authentication_failed", action: "attempt_login", suspicious: true, severity: "medium", sourceSystem: "cowrie", service: "ssh" };
    }
    return { eventType: "routine_connection", action: "read", suspicious: false, severity: "low", sourceSystem: "zeek", service: "web" };
  }
  const stages = [
    { eventType: "service_observed", action: "inspect_service", suspicious: true, severity: "low", sourceSystem: "zeek", service: "web" },
    { eventType: "authentication_failed", action: "attempt_login", suspicious: true, severity: "medium", sourceSystem: "cowrie", service: "credential-decoy" },
    { eventType: "database_decoy_interaction", action: "query", suspicious: true, severity: "high", sourceSystem: "suricata", service: "database-decoy" },
  ];
  return stages[index % stages.length];
}

function decoyFor(event, strategy) {
  if (strategy === "static") return "file-decoy";
  if (event.service.includes("credential") || event.action === "attempt_login") return "credential-decoy";
  if (event.service.includes("database") || event.action === "query") return "database-decoy";
  if (event.eventType === "service_observed") return "service-decoy";
  return "file-decoy";
}

const ALLOWED_DECOY_CATEGORIES = new Set(["file-decoy", "credential-decoy", "database-decoy", "service-decoy"]);

export function validateSandboxBundle(bundle, runId) {
  const issues = [];
  if (!bundle || bundle.schemaVersion !== 1 || bundle.syntheticOnly !== true) issues.push("unsupported or non-synthetic bundle header");
  if (!Array.isArray(bundle?.decoys) || bundle.decoys.length > 4) issues.push("invalid decoy list");
  const ids = new Set();
  for (const decoy of bundle?.decoys || []) {
    if (typeof decoy.id !== "string" || !decoy.id.startsWith(`${runId}-decoy-`) || ids.has(decoy.id)) issues.push("invalid or duplicate synthetic decoy identifier");
    ids.add(decoy.id);
    if (!ALLOWED_DECOY_CATEGORIES.has(decoy.category)) issues.push("unsupported decoy category");
    if (decoy.syntheticOnly !== true || decoy.enabled !== false) issues.push("decoy must remain synthetic and disabled");
    if (Object.keys(decoy).some((key) => /password|credential|payload|command|private|actor|ip|url/i.test(key))) issues.push("bundle contains a prohibited field");
  }
  return { valid: issues.length === 0, issues };
}

function finalizeRun(input, events, { runId, seed, startedAt, elapsedMs = 0 }) {
  const authFailures = events.filter((event) => event.eventType === "authentication_failed").length;
  const authAttempts = events.filter((event) => event.action === "attempt_login").length;
  const serviceLabels = [...new Set(events.filter((event) => event.eventType === "service_observed").map((event) => event.service))];
  const decoyInteractions = events.filter((event) => event.eventType.includes("decoy_interaction")).length;
  const sources = [...new Set(events.map((event) => event.sourceSystem))];
  const alerts = [];
  const addAlert = (rule, severity, eventIds, explanation) => alerts.push({
    id: `${runId}-alert-${alerts.length + 1}`, rule, severity, eventIds, explanation,
  });

  if (authFailures >= 3) addAlert("repeated_authentication_failures", authFailures >= 6 ? "high" : "medium", events.filter((event) => event.eventType === "authentication_failed").map((event) => event.id), `${authFailures} simulated authentication failures crossed the rule threshold of 3.`);
  if (serviceLabels.length >= 3) addAlert("service_reconnaissance_pattern", "medium", events.filter((event) => event.eventType === "service_observed").map((event) => event.id), `${serviceLabels.length} distinct synthetic service labels were observed.`);
  if (decoyInteractions >= 2) addAlert("repeated_decoy_interaction", "medium", events.filter((event) => event.eventType.includes("decoy_interaction")).map((event) => event.id), `${decoyInteractions} synthetic decoy interactions were recorded.`);
  if (sources.length >= 2 && events.filter((event) => event.suspicious).length >= 2) addAlert("cross_source_synthetic_correlation", "high", events.filter((event) => event.suspicious).map((event) => event.id), `Suspicious synthetic activity appeared in ${sources.length} sensor categories.`);
  const spanSeconds = events.length > 1 ? (Date.parse(events.at(-1).timestamp) - Date.parse(events[0].timestamp)) / 1000 : 0;
  const suspiciousEvents = events.filter((event) => event.suspicious);
  if (suspiciousEvents.length >= 8 && spanSeconds <= 10) addAlert("unusual_interaction_frequency", "medium", suspiciousEvents.map((event) => event.id), `${suspiciousEvents.length} suspicious synthetic events occurred within ${spanSeconds.toFixed(1)} seconds.`);

  const incidents = alerts.length === 0 ? [] : [{
    id: `${runId}-incident-1`, severity: alerts.some((alert) => alert.severity === "high") ? "high" : "medium",
    rules: alerts.map((alert) => alert.rule), eventIds: [...new Set(alerts.flatMap((alert) => alert.eventIds))],
    explanation: `Correlated ${alerts.length} deterministic rule signal${alerts.length === 1 ? "" : "s"} from this run. This is a triage example, not proof of compromise.`,
  }];

  const anomalyScore = Math.min(1, Number((authAttempts * 0.04 + authFailures * 0.025 + serviceLabels.length * 0.075 + decoyInteractions * 0.04 + incidents.length * 0.12).toFixed(3)));
  const classification = authAttempts >= 2 ? "authentication probing" : serviceLabels.length >= 3 ? "service reconnaissance" : decoyInteractions > 0 ? "decoy interaction" : events.some((event) => event.suspicious) ? "mixed suspicious activity" : "benign control activity";
  const features = { authenticationAttempts: authAttempts, authenticationFailures: authFailures, distinctServices: serviceLabels.length, decoyInteractions, sensorsObserved: sources.length };
  const profile = events.length ? {
    classification, interactions: events.length, features, anomalyScore,
    explanation: `${classification} based on ${authAttempts} login attempts (${authFailures} explicit failure events), ${serviceLabels.length} distinct service observations, and ${decoyInteractions} decoy interactions.`,
    assessment: "Transparent sandbox heuristic; not the trained profile model or a probability of compromise.",
  } : null;

  const recommendations = [];
  if (authAttempts > 0) recommendations.push({ id: `${runId}-rec-auth`, category: "authentication_decoys", title: "Add synthetic authentication decoys", rationale: `${authAttempts} login attempt(s) were observed in this sandbox run.` });
  if (serviceLabels.length >= 2) recommendations.push({ id: `${runId}-rec-service`, category: "service_diversity", title: "Expand simulated service diversity", rationale: `${serviceLabels.length} synthetic service labels were observed.` });
  if (events.some((event) => event.eventType === "database_decoy_interaction") && authAttempts > 0) recommendations.push({ id: `${runId}-rec-path`, category: "expanded_decoy_path", title: "Offer an alternate synthetic interaction path", rationale: "Credential and database stages both appeared in the simulated sequence." });

  const observedDecoys = [...new Set(events.map((event) => event.decoyCategory))];
  const syntheticDecoys = observedDecoys.map((category) => ({ id: `${runId}-decoy-${category}`, category, syntheticOnly: true, enabled: false }));
  const bundleValidation = validateSandboxBundle({ schemaVersion: 1, syntheticOnly: true, decoys: syntheticDecoys }, runId);
  const benignEvents = events.filter((event) => !event.suspicious);
  const falsePositiveEvents = [...new Set(alerts.flatMap((alert) => alert.eventIds))].filter((eventId) => events.some((event) => event.id === eventId && !event.suspicious));
  const selectedStrategy = input.strategy === "static" ? "static_file_decoy" : authAttempts > 0 && events.some((event) => event.eventType === "database_decoy_interaction") ? "expanded_decoy_path" : authAttempts > 0 ? "credential_decoy" : serviceLabels.length > 0 ? "service_decoy" : "neutral_response";
  return {
    runId, scenario: input.scenario, scenarioLabel: SCENARIOS[input.scenario].label, intensity: input.intensity,
    strategy: input.strategy, seed, startedAt: new Date(startedAt).toISOString(), eventWindowEnd: new Date(Date.parse(startedAt) + Math.max(0, events.length - 1) * INTENSITIES[input.intensity] * 1000).toISOString(),
    elapsedMs, attempted: input.interactionCount, recorded: events.length, completion: events.length === input.interactionCount ? "completed" : "incomplete",
    events, alerts, incidents, profile, recommendations, selectedStrategy, observedDecoys, syntheticDecoys, decoyCoverage: observedDecoys.length,
    sensorCategories: sources, ruleCoverage: alerts.length, bundleValidation, bundleValidationFailures: bundleValidation.valid ? 0 : 1,
    strategyChanges: input.strategy === "adaptive" && selectedStrategy !== "neutral_response" ? 1 : 0,
    benignEvents: benignEvents.length,
    falsePositiveEvents: falsePositiveEvents.length,
    falsePositiveRate: benignEvents.length ? Number((falsePositiveEvents.length / benignEvents.length).toFixed(3)) : null,
    summary: `${events.length} of ${input.interactionCount} synthetic interactions were generated; ${alerts.length} rule alert(s), ${incidents.length} correlated incident(s), and ${observedDecoys.length} decoy category/categories observed.`,
  };
}

function makeEvent(input, index, random, runId, startedAt) {
  const activity = activityFor(input.scenario, index, random, input.intensity);
  let sourceSystem = activity.sourceSystem;
  if (input.scenario === "mixed_activity" && activity.suspicious) sourceSystem = "suricata";
  const eventId = `${runId}-event-${String(index + 1).padStart(2, "0")}`;
  return {
    id: eventId, timestamp: new Date(Date.parse(startedAt) + index * INTENSITIES[input.intensity] * 1000).toISOString(),
    sourceIdentifier: `synthetic-origin-${String((index % (input.intensity === "high" ? 3 : 2)) + 1).padStart(2, "0")}`,
    sourceSystem, eventType: activity.eventType, action: activity.action, service: activity.service,
    severity: activity.severity, suspicious: activity.suspicious, decoyCategory: decoyFor(activity, input.strategy),
    summary: `${activity.action.replaceAll("_", " ")} against synthetic ${activity.service} activity.`,
  };
}

export function runSandboxSimulation(input, options = {}) {
  const valid = validateSandboxInput(input);
  const startedAt = options.startedAt || "2026-01-01T00:00:00.000Z";
  const seed = valid.seed ?? 0;
  const runId = options.runId || `sandbox-${seed}`;
  const random = seededRandom(seed);
  const events = Array.from({ length: valid.interactionCount }, (_, index) => makeEvent(valid, index, random, runId, startedAt));
  return finalizeRun(valid, events, { runId, seed, startedAt, elapsedMs: options.elapsedMs || 0 });
}

export async function runSandboxSimulationAsync(input, options = {}) {
  const valid = validateSandboxInput(input);
  const startedAt = options.startedAt || new Date().toISOString();
  const seed = valid.seed ?? Math.floor(Math.random() * MAX_SANDBOX_SEED);
  const runId = options.runId || `sandbox-${seed}`;
  const random = seededRandom(seed);
  const events = [];
  const timer = () => new Promise((resolve) => setTimeout(resolve, 0));
  const startClock = globalThis.performance?.now?.() ?? Date.now();
  for (let index = 0; index < valid.interactionCount; index += 1) {
    events.push(makeEvent(valid, index, random, runId, startedAt));
    options.onProgress?.(events.length, valid.interactionCount);
    await timer();
  }
  const elapsedMs = Number(((globalThis.performance?.now?.() ?? Date.now()) - startClock).toFixed(2));
  return finalizeRun(valid, events, { runId, seed, startedAt, elapsedMs });
}

export function evaluateSandboxRecommendation(run, recommendation) {
  if (!run || !recommendation || !run.recommendations.some((item) => item.id === recommendation.id)) {
    throw new TypeError("Recommendation must belong to the current sandbox run.");
  }
  const startedAt = globalThis.performance?.now?.() ?? Date.now();
  const replay = runSandboxSimulation({
    scenario: run.scenario, interactionCount: run.attempted, intensity: run.intensity, strategy: run.strategy, seed: run.seed,
  }, { runId: `${run.runId}-evaluation`, startedAt: run.startedAt });
  const elapsedMs = Number(((globalThis.performance?.now?.() ?? Date.now()) - startedAt).toFixed(2));
  const evidencePresent = recommendation.category === "authentication_decoys"
    ? replay.profile.features.authenticationAttempts > 0
    : recommendation.category === "service_diversity"
      ? replay.profile.features.distinctServices >= 2
      : recommendation.category === "expanded_decoy_path"
        ? replay.events.some((event) => event.eventType === "database_decoy_interaction") && replay.profile.features.authenticationAttempts > 0
        : false;
  const runComplete = run.completion === "completed" && run.recorded === run.attempted && run.bundleValidationFailures === 0;
  const passed = runComplete && replay.recorded === replay.attempted && replay.bundleValidationFailures === 0 && evidencePresent;
  return {
    outcome: passed ? "passed" : "failed", interactionsAttempted: run.attempted, interactionsRecorded: run.recorded,
    replayInteractionsRecorded: replay.recorded, bundleValidationFailures: run.bundleValidationFailures, evidencePresent,
    elapsedMs, note: "Deterministic isolated replay of this synthetic scenario; not an effectiveness claim or backend approval.",
  };
}

export function compareSandboxStrategies(input, repetitions = 3) {
  const valid = validateSandboxInput(input);
  if (!Number.isInteger(repetitions) || repetitions < 1 || repetitions > 5) throw new RangeError("Comparison repetitions must be between 1 and 5.");
  const runs = [];
  for (let repetition = 0; repetition < repetitions; repetition += 1) {
    const seed = ((valid.seed ?? 0) + repetition) >>> 0;
    for (const strategy of ["static", "adaptive"]) {
      const config = { ...valid, seed, strategy };
      runs.push(runSandboxSimulation(config, { runId: `compare-${repetition + 1}-${strategy}`, startedAt: "2026-01-01T00:00:00.000Z" }));
    }
  }
  const summarize = (strategy) => {
    const samples = runs.filter((run) => run.strategy === strategy);
    const average = (select) => Number((samples.reduce((sum, run) => sum + select(run), 0) / samples.length).toFixed(2));
    const falsePositiveRates = samples.map((run) => run.benignEvents ? run.falsePositiveEvents / run.benignEvents : null).filter((value) => value !== null);
    return {
      strategy, repetitions: samples.length, meanInteractionsRecorded: average((run) => run.recorded),
      meanDecoyCoverage: average((run) => run.decoyCoverage), meanAlertCount: average((run) => run.alerts.length),
      meanRuleCoverage: average((run) => run.ruleCoverage), completionRate: average((run) => run.completion === "completed" ? 1 : 0),
      meanStrategyChanges: average((run) => run.strategyChanges),
      falsePositiveRate: falsePositiveRates.length ? Number((falsePositiveRates.reduce((sum, value) => sum + value, 0) / falsePositiveRates.length).toFixed(3)) : null,
    };
  };
  return { runs, static: summarize("static"), adaptive: summarize("adaptive"), note: "Paired synthetic runs share each repetition seed. Results describe this sandbox model only; adaptive strategy is not guaranteed to outperform static." };
}

export function publishSandboxIndicator(exchange, run, alert) {
  if (!exchange || !Array.isArray(exchange.history) || !run?.alerts?.some((item) => item.id === alert?.id)) throw new TypeError("Choose an alert from the current sandbox run.");
  const allowedRules = new Set(["repeated_authentication_failures", "service_reconnaissance_pattern", "repeated_decoy_interaction", "cross_source_synthetic_correlation", "unusual_interaction_frequency"]);
  if (!allowedRules.has(alert.rule)) throw new TypeError("Unsupported synthetic indicator.");
  const indicator = `sandbox-rule:${alert.rule}`;
  if (exchange.received.some((item) => item.indicator === indicator)) return { ...exchange, history: [...exchange.history, { action: "duplicate", indicator, status: "duplicate_ignored" }].slice(-100) };
  const record = { indicator, origin: "Simulated Node A", receiver: "Simulated Node B", status: "pending_review", validation: "allowlisted rule identifier", runId: run.runId };
  return { received: [...exchange.received, record].slice(-20), history: [...exchange.history, { action: "published_and_received", indicator, status: record.status }].slice(-100) };
}

export function reviewSandboxIndicator(exchange, indicator, decision) {
  if (!new Set(["approved", "rejected"]).has(decision)) throw new TypeError("Review decision must be approved or rejected.");
  let updated = false;
  const received = exchange.received.map((record) => {
    if (record.indicator !== indicator || record.status !== "pending_review") return record;
    updated = true;
    return { ...record, status: decision };
  });
  if (!updated) throw new TypeError("Only a pending received indicator can be reviewed.");
  return { received, history: [...exchange.history, { action: "operator_review", indicator, status: decision }].slice(-100) };
}

export function createEmptySandboxState() {
  return { run: null, comparison: null, evaluations: {}, reviewStates: {}, exchange: { received: [], history: [] } };
}

export function resetSandboxState() {
  return createEmptySandboxState();
}
