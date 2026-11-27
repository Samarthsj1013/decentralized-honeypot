import { useMemo, useState } from "react";
import {
  SANDBOX_SCENARIOS,
  MAX_SANDBOX_INTERACTIONS,
  MAX_SANDBOX_SEED,
  compareSandboxStrategies,
  createEmptySandboxState,
  evaluateSandboxRecommendation,
  filterSandboxEvents,
  normalizeIntegerInput,
  publishSandboxIndicator,
  resetSandboxState,
  reviewSandboxIndicator,
  runSandboxSimulationAsync,
} from "./sandbox-engine.js";

const INITIAL_SETTINGS = { scenario: "ssh_authentication_probing", interactionCount: 8, intensity: "medium", strategy: "adaptive", seed: 20261126 };

export default function InteractiveSandbox() {
  const [settings, setSettings] = useState(INITIAL_SETTINGS);
  const [state, setState] = useState(createEmptySandboxState);
  const [status, setStatus] = useState("idle");
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState("");
  const [eventTypeFilter, setEventTypeFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [sortOrder, setSortOrder] = useState("newest");
  const [repetitions, setRepetitions] = useState(3);
  const [comparisonStatus, setComparisonStatus] = useState("idle");
  const [runSequence, setRunSequence] = useState(0);
  const [indicatorChoice, setIndicatorChoice] = useState("");

  const visibleEvents = useMemo(() => {
    if (!state.run) return [];
    return filterSandboxEvents(state.run.events, { eventType: eventTypeFilter, severity: severityFilter, sortOrder });
  }, [state.run, eventTypeFilter, severityFilter, sortOrder]);

  function updateSetting(key, value) {
    setSettings((current) => ({ ...current, [key]: value }));
  }

  function normalizeIntegerField(event, key, minimum, maximum) {
    const normalized = normalizeIntegerInput(event.currentTarget.value, minimum, maximum);
    if (normalized === null) return;
    event.currentTarget.value = normalized;
    updateSetting(key, Number(normalized));
  }

  async function runSimulation(event) {
    event?.preventDefault();
    if (status === "running") return;
    setError("");
    setState(resetSandboxState());
    setProgress(0);
    setStatus("running");
    const sequence = runSequence + 1;
    setRunSequence(sequence);
    try {
      const input = { ...settings, seed: settings.seed === "" ? null : Number(settings.seed) };
      const run = await runSandboxSimulationAsync(input, {
        runId: `sandbox-run-${sequence}`,
        onProgress: (done, total) => setProgress(Math.round((done / total) * 100)),
      });
      setState({ ...createEmptySandboxState(), run, exchange: { received: [], history: [] } });
      setStatus("completed");
      setProgress(100);
      setEventTypeFilter("all");
      setSeverityFilter("all");
      setIndicatorChoice(run.alerts[0]?.id || "");
    } catch (runError) {
      setStatus("failed");
      setError(runError.message || "The bounded simulation could not be completed.");
    }
  }

  function reset() {
    setState(resetSandboxState());
    setSettings(INITIAL_SETTINGS);
    setStatus("idle");
    setProgress(0);
    setError("");
    setRunSequence(0);
    setComparisonStatus("idle");
    setEventTypeFilter("all");
    setSeverityFilter("all");
  }

  async function compare() {
    if (!state.run || comparisonStatus === "running") return;
    setComparisonStatus("running");
    setError("");
    await new Promise((resolve) => setTimeout(resolve, 0));
    try {
      const input = { ...settings, seed: state.run.seed };
      const comparison = compareSandboxStrategies(input, Number(repetitions));
      setState((current) => ({ ...current, comparison }));
      setComparisonStatus("completed");
    } catch (compareError) {
      setError(compareError.message || "Comparison failed.");
      setComparisonStatus("failed");
    }
  }

  function evaluateRecommendation(recommendation) {
    try {
      const evaluation = evaluateSandboxRecommendation(state.run, recommendation);
      setState((current) => ({ ...current, evaluations: { ...current.evaluations, [recommendation.id]: evaluation } }));
    } catch (evaluationError) {
      setError(evaluationError.message || "Evaluation failed.");
    }
  }

  function reviewIndicator(indicator, decision) {
    try {
      setState((current) => ({ ...current, exchange: reviewSandboxIndicator(current.exchange, indicator, decision) }));
    } catch (reviewError) {
      setError(reviewError.message || "Review could not be recorded.");
    }
  }

  const run = state.run;

  return <>
    <section className="sandbox-hero" aria-labelledby="sandbox-hero-title">
      <div><span className="eyebrow">INTERACTIVE SECURITY SANDBOX · SYNTHETIC DATA</span><h2 id="sandbox-hero-title">Explore the honeypot workflow</h2><p>Choose a bounded scenario and run its synthetic event sequence in this browser tab. Nothing is sent to the operational API.</p></div>
      <a className="primary-button sandbox-launch" href="#sandbox">Open Simulation Lab <span aria-hidden="true">→</span></a>
    </section>

    <section className="sandbox-section" id="sandbox" aria-labelledby="sandbox-title">
      <div className="section-heading"><div><span className="eyebrow">SIMULATION LAB</span><h2 id="sandbox-title">Run a synthetic scenario</h2><p>Events are generated locally from these settings. Maximum {MAX_SANDBOX_INTERACTIONS} interactions per run.</p></div><span className={`sandbox-state state-${status}`} role="status">{status === "idle" ? "Ready" : status}</span></div>
      <form className="sandbox-form" onSubmit={runSimulation}>
        <label>Scenario<select value={settings.scenario} onChange={(event) => updateSetting("scenario", event.target.value)} disabled={status === "running"}>{SANDBOX_SCENARIOS.map((scenario) => <option key={scenario.value} value={scenario.value}>{scenario.label}</option>)}</select></label>
        <label>Interactions (1–{MAX_SANDBOX_INTERACTIONS})<input type="number" min="1" max={MAX_SANDBOX_INTERACTIONS} value={settings.interactionCount} onChange={(event) => updateSetting("interactionCount", Number(event.target.value))} onBlur={(event) => normalizeIntegerField(event, "interactionCount", 1, MAX_SANDBOX_INTERACTIONS)} disabled={status === "running"} /></label>
        <label>Intensity<select value={settings.intensity} onChange={(event) => updateSetting("intensity", event.target.value)} disabled={status === "running"}><option value="low">Low · 12 sec interval</option><option value="medium">Medium · 3 sec interval</option><option value="high">High · 0.5 sec interval</option></select></label>
        <label>Honeypot strategy<select value={settings.strategy} onChange={(event) => updateSetting("strategy", event.target.value)} disabled={status === "running"}><option value="static">Static</option><option value="adaptive">Behavior-conditioned</option></select></label>
        <label>Reproducible seed<input type="number" min="0" max={MAX_SANDBOX_SEED} value={settings.seed} onChange={(event) => updateSetting("seed", event.target.value === "" ? "" : Number(event.target.value))} onBlur={(event) => normalizeIntegerField(event, "seed", 0, MAX_SANDBOX_SEED)} disabled={status === "running"} /><small>Leave blank for a generated seed.</small></label>
        <div className="sandbox-actions"><button className="primary-button" type="submit" disabled={status === "running"}>{run ? "Run Another Scenario" : "Run Simulation"}</button><button className="secondary-button" type="button" onClick={reset} disabled={status === "running"}>Reset Sandbox</button></div>
      </form>
      {status === "running" && <div className="sandbox-progress"><div><span>Generating bounded events</span><span>{progress}%</span></div><progress max="100" value={progress} aria-label={`Generating synthetic interactions, ${progress}% complete`} /></div>}
      {error && <div className="alert alert-error" role="alert"><strong>Sandbox action failed</strong><span>{error}</span></div>}
      {!run && status !== "running" && <div className="sandbox-empty"><strong>No sandbox run yet</strong><span>Pick a scenario and start. The published lab baseline remains available in its separate section below.</span></div>}
      {run && <>
        <div className="sandbox-result-heading"><div><span className="eyebrow">CURRENT BROWSER RUN · {run.scenarioLabel}</span><h3>{run.summary}</h3><p>Sensors: {run.sensorCategories.join(", ") || "none"} · Run ID: <code>{run.runId}</code> · Seed: <code>{run.seed}</code> · Virtual event window ends {new Date(run.eventWindowEnd).toLocaleString()}</p></div><span className={`sandbox-state state-${run.completion}`}>{run.completion}</span></div>
        <div className="sandbox-kpis" aria-label="Current synthetic run measurements">
          <Metric label="Interactions" value={`${run.recorded}/${run.attempted}`} />
          <Metric label="Alert signals" value={run.alerts.length} />
          <Metric label="Incidents" value={run.incidents.length} />
          <Metric label="Behavior profiles" value={run.profile ? 1 : 0} />
          <Metric label="Recommendations" value={run.recommendations.length} />
          <Metric label="Decoy categories" value={run.decoyCoverage} />
          <Metric label="Strategy changes" value={run.strategyChanges} />
          <Metric label="Heuristic score" value={run.profile ? run.profile.anomalyScore.toFixed(3) : "—"} />
          <Metric label="Elapsed" value={`${run.elapsedMs} ms`} />
        </div>
        <p className="sandbox-honesty-note">Measurements above belong only to the current synthetic run. They do not replace or update the published controlled-lab baseline.</p>

        <section className="sandbox-subsection" id="sandbox-telemetry" aria-labelledby="sandbox-telemetry-title">
          <div className="sandbox-subheading"><div><span className="eyebrow">EVENT TIMELINE</span><h3 id="sandbox-telemetry-title">Generated telemetry</h3></div><div className="sandbox-filters">
            <label>Event type<select value={eventTypeFilter} onChange={(event) => setEventTypeFilter(event.target.value)}><option value="all">All types</option>{[...new Set(run.events.map((item) => item.eventType))].map((type) => <option key={type}>{type}</option>)}</select></label>
            <label>Severity<select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}><option value="all">All severity</option>{[...new Set(run.events.map((item) => item.severity))].map((severity) => <option key={severity}>{severity}</option>)}</select></label>
            <label>Order<select value={sortOrder} onChange={(event) => setSortOrder(event.target.value)}><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select></label>
          </div></div>
          <div className="sandbox-table-wrap"><table className="sandbox-table"><thead><tr><th>Time</th><th>Type</th><th>Source</th><th>Sensor</th><th>Severity</th><th>Interaction summary</th><th>Decoy</th></tr></thead><tbody>
            {visibleEvents.map((event) => <tr key={event.id}><td>{new Date(event.timestamp).toLocaleTimeString()}</td><td>{event.eventType}</td><td>{event.sourceIdentifier}</td><td>{event.sourceSystem}</td><td><span className={`sandbox-severity severity-${event.severity}`}>{event.severity}</span></td><td>{event.summary}</td><td>{event.decoyCategory}</td></tr>)}
          </tbody></table>{visibleEvents.length === 0 && <p className="sandbox-empty">No events match these filters.</p>}</div>
        </section>

        <div className="sandbox-analysis-grid">
          <section className="sandbox-subsection" id="sandbox-detection" aria-labelledby="sandbox-detection-title"><div className="sandbox-subheading"><div><span className="eyebrow">DETERMINISTIC RULES</span><h3 id="sandbox-detection-title">Alerts &amp; incidents</h3></div><span>{run.alerts.length} signals</span></div>
            {run.alerts.length === 0 ? <div className="sandbox-empty">No configured sandbox rule matched this run. That does not establish the activity as benign.</div> : <div className="sandbox-card-list">{run.alerts.map((alert) => <article className="sandbox-result-card" key={alert.id}><div className="sandbox-card-title"><strong>{alert.rule}</strong><span className={`sandbox-severity severity-${alert.severity}`}>{alert.severity}</span></div><p>{alert.explanation}</p><small>Supporting events: {alert.eventIds.length} · {alert.eventIds.slice(0, 4).join(", ")}{alert.eventIds.length > 4 ? "…" : ""}</small></article>)}</div>}
            <div className="sandbox-incident-summary"><strong>Correlated incidents: {run.incidents.length}</strong>{run.incidents.map((incident) => <p key={incident.id}>{incident.explanation}<small>Rules: {incident.rules.join(", ")}</small></p>)}</div>
          </section>
          <section className="sandbox-subsection" id="sandbox-profiles" aria-labelledby="sandbox-profile-title"><div className="sandbox-subheading"><div><span className="eyebrow">FEATURE-BASED ASSESSMENT</span><h3 id="sandbox-profile-title">Behavior profile</h3></div></div>
            {run.profile ? <><div className="sandbox-profile-score"><strong>{run.profile.classification}</strong><span>Heuristic score <b>{run.profile.anomalyScore.toFixed(3)}</b></span><div role="meter" aria-label="Heuristic anomaly score" aria-valuemin="0" aria-valuemax="1" aria-valuenow={run.profile.anomalyScore}><i style={{ width: `${run.profile.anomalyScore * 100}%` }} /></div></div><p>{run.profile.explanation}</p><div className="sandbox-feature-list">{Object.entries(run.profile.features).map(([feature, value]) => <span key={feature}>{feature.replace(/[A-Z]/g, (letter) => ` ${letter.toLowerCase()}`)} <b>{value}</b></span>)}</div><small className="sandbox-muted">{run.profile.assessment}</small></> : <div className="sandbox-empty">No events are available for profiling.</div>}
          </section>
        </div>

        <section className="sandbox-subsection" id="sandbox-deception" aria-labelledby="sandbox-deception-title"><div className="sandbox-subheading"><div><span className="eyebrow">SANDBOX STATE ONLY · NO ENFORCEMENT</span><h3 id="sandbox-deception-title">Adaptive deception recommendations</h3><p>Selected simulated strategy: <strong>{run.selectedStrategy}</strong> · {run.observedDecoys.length} observed decoy category/categories</p></div></div>
          <div className="sandbox-decoy-list" aria-label="Generated disabled synthetic decoys"><strong>Generated decoy templates · disabled</strong>{run.syntheticDecoys.map((decoy) => <span key={decoy.id}><code>{decoy.category}</code> · {decoy.id} · synthetic only</span>)}<small>Bundle schema validation: {run.bundleValidation.valid ? "passed" : `failed (${run.bundleValidation.issues.join(", ")})`}</small></div>
          {run.recommendations.length === 0 ? <div className="sandbox-empty">No recommendation was generated because this run did not show a configured trigger feature.</div> : <div className="sandbox-card-list">{run.recommendations.map((recommendation) => {
            const evaluation = state.evaluations[recommendation.id];
            const review = state.reviewStates?.[recommendation.id] || "pending";
            return <article className="sandbox-result-card" key={recommendation.id}><div className="sandbox-card-title"><strong>{recommendation.title}</strong><span className="sandbox-state">{review}</span></div><p>{recommendation.rationale}</p>
              {evaluation && <div className={`sandbox-evaluation ${evaluation.outcome}`}><strong>Isolated replay: {evaluation.outcome}</strong><span>Current run {evaluation.interactionsRecorded}/{evaluation.interactionsAttempted} interactions · replay {evaluation.replayInteractionsRecorded} recorded · bundle validation failures: {evaluation.bundleValidationFailures} · {evaluation.elapsedMs} ms</span><small>{evaluation.note}</small></div>}
              <div className="sandbox-actions"><button className="secondary-button" onClick={() => evaluateRecommendation(recommendation)} disabled={Boolean(evaluation?.outcome === "passed") || review !== "pending"}>Evaluate locally</button>
                {evaluation?.outcome === "passed" && review === "pending" && <><button className="secondary-button" onClick={() => setState((current) => ({ ...current, reviewStates: { ...current.reviewStates, [recommendation.id]: "approved" } }))}>Approve in sandbox</button><button className="secondary-button" onClick={() => setState((current) => ({ ...current, reviewStates: { ...current.reviewStates, [recommendation.id]: "rejected" } }))}>Reject</button></>}
              </div>
            </article>;
          })}</div>}
          <p className="sandbox-muted">Evaluation replays this deterministic synthetic input and validates local completion/evidence. Approval changes only this tab's sandbox state; no backend policy, decoy, service, or infrastructure is changed.</p>
        </section>

        <section className="sandbox-subsection" id="sandbox-comparison" aria-labelledby="sandbox-comparison-title"><div className="sandbox-subheading"><div><span className="eyebrow">PAIRED SYNTHETIC EXPERIMENT</span><h3 id="sandbox-comparison-title">Static vs adaptive strategy</h3><p>Both strategies receive the same scenario inputs and seed per repetition.</p></div></div>
          <div className="sandbox-compare-controls"><label>Paired repetitions<select value={repetitions} onChange={(event) => setRepetitions(Number(event.target.value))}><option value={1}>1</option><option value={2}>2</option><option value={3}>3</option><option value={4}>4</option><option value={5}>5</option></select></label><button className="secondary-button" onClick={compare} disabled={!run || comparisonStatus === "running"}>{comparisonStatus === "running" ? "Computing paired runs…" : "Compare strategies"}</button></div>
          {state.comparison && <><div className="sandbox-compare-grid">{[state.comparison.static, state.comparison.adaptive].map((result) => <article key={result.strategy}><h4>{result.strategy} strategy</h4><Metric label="Mean interactions recorded" value={result.meanInteractionsRecorded} /><Metric label="Mean decoy coverage" value={result.meanDecoyCoverage} /><Metric label="Mean alerts" value={result.meanAlertCount} /><Metric label="Mean triggered rules" value={result.meanRuleCoverage} /><Metric label="Mean strategy changes" value={result.meanStrategyChanges} /><Metric label="Scenario completion" value={`${Math.round(result.completionRate * 100)}%`} /><Metric label="Synthetic false-positive rate" value={result.falsePositiveRate === null ? "Unavailable" : `${Math.round(result.falsePositiveRate * 100)}%`} /></article>)}</div><div className="sandbox-comparison-chart" role="img" aria-label="Paired comparison of mean decoy coverage by strategy">{comparisonChart("Mean decoy coverage", state.comparison.static.meanDecoyCoverage, state.comparison.adaptive.meanDecoyCoverage)}{comparisonChart("Mean alert count", state.comparison.static.meanAlertCount, state.comparison.adaptive.meanAlertCount)}</div><p className="sandbox-muted">{state.comparison.note} False-positive rate is unavailable: the sandbox does not emit event-level prediction labels independently of its suspicious ground-truth labels. No alert in the benign control is a scenario behavior check, not a measured false-positive rate.</p></>}
        </section>

        <section className="sandbox-subsection" id="sandbox-intelligence" aria-labelledby="sandbox-intelligence-title"><div className="sandbox-subheading"><div><span className="eyebrow">LOCAL EXCHANGE SIMULATION · NO CRYPTOGRAPHIC SIGNING</span><h3 id="sandbox-intelligence-title">Simulated intelligence exchange</h3><p>Publish a rule identifier from this run between isolated in-tab demo nodes.</p></div></div>
          {!run.alerts.length ? <div className="sandbox-empty">Generate a rule-based alert before sharing a synthetic indicator.</div> : <div className="sandbox-exchange-picker"><label>Alert rule<select value={indicatorChoice} onChange={(event) => setIndicatorChoice(event.target.value)}>{run.alerts.map((alert) => <option key={alert.id} value={alert.id}>{alert.rule}</option>)}</select></label><button className="secondary-button" onClick={() => { const alert = run.alerts.find((item) => item.id === indicatorChoice); if (alert) setState((current) => ({ ...current, exchange: publishSandboxIndicator(current.exchange, run, alert) })); }}>Publish from Node A to Node B</button></div>}
          {state.exchange.history.length > 0 && <ul className="sandbox-history">{state.exchange.history.map((entry, index) => <li key={`${entry.indicator}-${index}`}><strong>{entry.action.replaceAll("_", " ")}</strong><code>{entry.indicator}</code><span>{entry.status}</span></li>)}</ul>}
          {state.exchange.received.map((record) => <article className="sandbox-result-card" key={record.indicator}><div className="sandbox-card-title"><strong>{record.origin} → {record.receiver}</strong><span className="sandbox-state">{record.status}</span></div><p>{record.indicator} · validation: {record.validation}</p>{record.status === "pending_review" && <div className="sandbox-actions"><button className="secondary-button" onClick={() => reviewIndicator(record.indicator, "approved")}>Approve locally</button><button className="secondary-button" onClick={() => reviewIndicator(record.indicator, "rejected")}>Reject locally</button></div>}</article>)}
          <p className="sandbox-muted">This exchange is a browser-only demonstration. It has no network transport, signatures, trusted keys, publisher identity, persistence, or blockchain consensus. It never shares addresses, actor IDs, credentials, or event payloads.</p>
        </section>
      </>}
    </section>
  </>;
}

function Metric({ label, value }) {
  return <div className="sandbox-metric"><span>{label}</span><strong>{value}</strong></div>;
}

function comparisonChart(label, staticValue, adaptiveValue) {
  const max = Math.max(staticValue, adaptiveValue, 1);
  return <section className="sandbox-chart-row" aria-label={label} key={label}><strong>{label}</strong><div><span>Static</span><div className="sandbox-bar"><i style={{ width: `${(staticValue / max) * 100}%` }} /></div><b>{staticValue}</b></div><div><span>Adaptive</span><div className="sandbox-bar adaptive"><i style={{ width: `${(adaptiveValue / max) * 100}%` }} /></div><b>{adaptiveValue}</b></div></section>;
}
