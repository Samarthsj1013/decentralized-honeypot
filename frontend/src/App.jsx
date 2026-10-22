import { useEffect, useMemo, useState } from "react";
import { API_BASE_URL, getEvaluation, getScenarios, runEvaluation } from "./api.js";
import {
  formatLatency,
  formatPercent,
  formatRatio,
  getScenarioMetricRows,
  getStrategyTimeline,
  scenarioShortName,
} from "./dashboard-data.js";

function makeEvaluationId() {
  const token = globalThis.crypto?.randomUUID?.().replaceAll("-", "")
    || `${Date.now().toString(16)}${Math.random().toString(16).slice(2)}`;
  return `eval-${token.slice(0, 10)}`;
}

function Icon({ name, size = 18 }) {
  const common = {
    width: size,
    height: size,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round",
    strokeLinejoin: "round",
    "aria-hidden": true,
  };
  const paths = {
    shield: <><path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3Z" /><path d="m9 12 2 2 4-4" /></>,
    chart: <><path d="M4 19V5" /><path d="M4 19h17" /><path d="m7 15 4-4 3 2 6-7" /></>,
    runs: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M8 9h8M8 13h5M8 17h8" /></>,
    pulse: <><path d="M3 12h4l3-7 4 14 3-7h4" /></>,
    layers: <><path d="m12 3 9 5-9 5-9-5 9-5Z" /><path d="m3 12 9 5 9-5M3 16l9 5 9-5" /></>,
    refresh: <><path d="M20 7v5h-5" /><path d="M4 17v-5h5" /><path d="M5.6 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.4-3" /></>,
    play: <path d="m8 5 11 7-11 7V5Z" fill="currentColor" stroke="none" />,
    search: <><circle cx="10.8" cy="10.8" r="6.8" /><path d="m16 16 4.5 4.5" /></>,
    arrow: <><path d="M5 12h14" /><path d="m13 6 6 6-6 6" /></>,
    menu: <><path d="M4 6h16M4 12h16M4 18h16" /></>,
  };
  return <svg {...common}>{paths[name] || paths.chart}</svg>;
}

function StatusPill({ status }) {
  const label = status === "connected" ? "API connected" : status === "checking" ? "Checking API" : "API unavailable";
  return <span className={`connection-pill connection-${status}`}><span className="status-dot" />{label}</span>;
}

function KpiCard({ label, value, detail, icon, tone = "teal" }) {
  return (
    <article className="kpi-card">
      <div className="kpi-topline">
        <span className="kpi-label">{label}</span>
        <span className={`kpi-icon icon-${tone}`}><Icon name={icon} size={17} /></span>
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-detail">{detail}</div>
    </article>
  );
}

function ScenarioChart({ title, subtitle, rows, metric, unit, color, maxValue }) {
  const width = 620;
  const height = 238;
  const baseline = 178;
  const top = 26;
  const plotHeight = baseline - top;
  const chartMax = maxValue ?? Math.max(1, ...rows.map((row) => Number.isFinite(row[metric]) ? row[metric] : 0));
  const positions = rows.map((_, index) => 62 + index * 119);
  const formatValue = (value) => {
    if (!Number.isFinite(value)) return "Unavailable";
    if (unit === "%") return `${(value * 100).toFixed(0)}%`;
    if (unit === "ms") return `${value.toFixed(1)} ms`;
    return value.toLocaleString();
  };

  return (
    <article className="panel chart-panel">
      <div className="panel-heading">
        <div><h3>{title}</h3><p>{subtitle}</p></div>
        <span className="chart-mark" style={{ "--chart-color": color }} />
      </div>
      {rows.length === 0 ? <ChartEmpty /> : (
        <svg className="bar-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`${title} comparison across scenarios`}>
          {[0, 0.5, 1].map((fraction) => {
            const y = baseline - plotHeight * fraction;
            return <g key={fraction}>
              <line x1="34" x2="602" y1={y} y2={y} className="chart-grid" />
              <text x="28" y={y + 4} className="chart-axis-label" textAnchor="end">{formatValue(chartMax * fraction)}</text>
            </g>;
          })}
          {rows.map((row, index) => {
            const value = row[metric];
            const x = positions[index];
            const measured = Number.isFinite(value);
            const barHeight = measured ? Math.max(value > 0 ? 2 : 0, (value / chartMax) * plotHeight) : 0;
            const y = baseline - barHeight;
            return <g key={row.name}>
              {measured ? <rect x={x - 19} y={y} width="38" height={barHeight} rx="5" fill={color} className="chart-bar">
                <title>{`${row.label}: ${formatValue(value)}`}</title>
              </rect> : <line x1={x - 10} x2={x + 10} y1={baseline - 4} y2={baseline - 4} className="chart-unavailable" />}
              <text x={x} y={Math.max(top - 7, y - 9)} className="chart-value" textAnchor="middle">{measured ? formatValue(value) : "—"}</text>
              <text x={x} y="204" className="chart-category" textAnchor="middle">{row.label}</text>
            </g>;
          })}
        </svg>
      )}
    </article>
  );
}

function ChartEmpty() {
  return <div className="chart-empty">Run or load an evaluation to compare scenario measurements.</div>;
}

function StrategyTimeline({ evaluation }) {
  const rows = getStrategyTimeline(evaluation);
  return (
    <section className="panel timeline-panel">
      <div className="section-heading">
        <div><span className="eyebrow">ADAPTIVE RESPONSE</span><h2>Strategy transitions</h2><p>Recorded strategy sequence for runs that report one.</p></div>
        {evaluation && <span className="subtle-count">{rows.length} measured runs</span>}
      </div>
      {!evaluation ? <div className="empty-state compact-empty"><span className="empty-symbol"><Icon name="pulse" size={20} /></span><h3>No strategy data yet</h3><p>Run an evaluation or look up a saved ID to inspect observed changes.</p></div>
        : rows.length === 0 ? <div className="chart-empty">The selected evaluation contains no reported strategy sequence.</div>
          : <div className="timeline-list">{rows.map((row) => (
            <article className="timeline-run" key={row.id}>
              <div className="timeline-run-head">
                <div><strong>{scenarioShortName(row.scenario)}</strong><span>Repetition {row.repetition}</span></div>
                <span className="run-id">{row.id}</span>
              </div>
              <ol className="strategy-sequence" aria-label={`Observed strategies for ${row.id}`}>
                {row.strategies.map((strategy, index) => <li key={`${strategy}-${index}`}>
                  <span className="sequence-node">{index + 1}</span><span>{strategy.replaceAll("_", " ")}</span>
                </li>)}
              </ol>
              <div className="generated-line"><Icon name="layers" size={15} />
                <span>{row.generatedCount} decoys generated</span>
                {row.generatedDecoyIds.length > 0 && <span className="generated-ids">{row.generatedDecoyIds.join(" · ")}</span>}
              </div>
            </article>
          ))}</div>}
    </section>
  );
}

function ScenarioTable({ evaluation }) {
  const rows = getScenarioMetricRows(evaluation);
  return (
    <section className="panel table-panel">
      <div className="section-heading"><div><span className="eyebrow">SCENARIO BREAKDOWN</span><h2>Scenario performance</h2><p>Measured aggregates returned by the evaluation API.</p></div></div>
      {!evaluation ? <ChartEmpty /> : <div className="table-scroll"><table>
        <thead><tr><th>Scenario</th><th>Completed</th><th>Events</th><th>Strategy change</th><th>Decoys</th><th>Median latency</th><th>Errors</th></tr></thead>
        <tbody>{evaluation.scenarios.map((scenario) => <tr key={scenario.scenario}>
          <th scope="row"><span className="scenario-name">{scenarioShortName(scenario.scenario)}</span><span className="scenario-key">{scenario.scenario}</span></th>
          <td><span className="table-main">{formatRatio(scenario.completed_runs, scenario.runs_requested)}</span><span className="table-sub">{formatPercent(scenario.completion_rate)}</span></td>
          <td><span className="table-main">{formatRatio(scenario.interactions_recorded, scenario.interactions_attempted)}</span><span className="table-sub">{formatPercent(scenario.event_recording_rate)}</span></td>
          <td>{formatPercent(scenario.strategy_change_rate)}</td>
          <td>{scenario.decoys_generated.toLocaleString()}</td>
          <td>{formatLatency(scenario.median_latency_ms)}</td>
          <td><span className={scenario.errors ? "error-number" : "quiet-number"}>{scenario.errors}</span></td>
        </tr>)}</tbody>
      </table></div>}
    </section>
  );
}

function RunDetails({ evaluation }) {
  return (
    <section className="panel run-panel">
      <div className="section-heading"><div><span className="eyebrow">TRACE DETAIL</span><h2>Individual runs</h2><p>Expand a run for its recorded actions, decoy IDs, and errors.</p></div>{evaluation && <span className="subtle-count">{evaluation.runs.length} runs</span>}</div>
      {!evaluation ? <ChartEmpty /> : <div className="run-list">{evaluation.runs.map((run) => {
        const summary = run.simulation_summary;
        const strategy = summary?.initial_adaptation_strategy && summary?.final_adaptation_strategy
          ? `${summary.initial_adaptation_strategy} → ${summary.final_adaptation_strategy}`
          : summary?.final_adaptation_strategy || "Unavailable";
        return <details className="run-detail" key={run.simulation_id}>
          <summary>
            <span className={`run-status status-${run.status}`}>{run.status}</span>
            <span className="run-scenario">{scenarioShortName(run.scenario)} <small>#{run.repetition}</small></span>
            <span className="run-actions">{formatRatio(summary?.interactions_recorded, summary?.interactions_attempted)}</span>
            <span className="run-latency">{formatLatency(summary ? summary.elapsed_seconds * 1000 : null)}</span>
            <span className="summary-chevron">⌄</span>
          </summary>
          <div className="run-expanded">
            <dl className="detail-grid">
              <div><dt>Expected actions</dt><dd>{run.scenario_expected_actions.join(" → ")}</dd></div>
              <div><dt>Action sequence match</dt><dd>{run.expected_action_sequence_match === null ? "Unavailable" : run.expected_action_sequence_match ? "Yes" : "No"}</dd></div>
              <div><dt>Initial → final strategy</dt><dd>{strategy}</dd></div>
              <div><dt>Strategy transitions</dt><dd>{summary?.strategy_change_count ?? "Unavailable"}</dd></div>
              <div><dt>Actor ID</dt><dd className="mono">{run.actor_id}</dd></div>
              <div><dt>Simulation ID</dt><dd className="mono">{run.simulation_id}</dd></div>
              <div className="detail-wide"><dt>Recorded actions</dt><dd>{summary?.observed_actions?.join(" → ") || "None recorded"}</dd></div>
              <div className="detail-wide"><dt>Observed decoys</dt><dd className="mono">{summary?.observed_decoys?.join(", ") || "None recorded"}</dd></div>
              <div className="detail-wide"><dt>Generated decoy IDs</dt><dd className="mono">{summary?.generated_decoy_ids?.join(", ") || "None"}</dd></div>
              {run.execution_error && <div className="detail-wide"><dt>Execution error</dt><dd className="error-copy">{run.execution_error}</dd></div>}
              {!!summary?.errors?.length && <div className="detail-wide"><dt>Interaction errors</dt><dd className="error-copy">{summary.errors.map((error) => `Step ${error.step}: ${error.message}`).join(" · ")}</dd></div>}
            </dl>
          </div>
        </details>;
      })}</div>}
    </section>
  );
}

export default function App() {
  const [scenarios, setScenarios] = useState([]);
  const [connection, setConnection] = useState("checking");
  const [evaluation, setEvaluation] = useState(null);
  const [evaluationId, setEvaluationId] = useState("");
  const [formId, setFormId] = useState(makeEvaluationId);
  const [repetitions, setRepetitions] = useState(3);
  const [repeatCount, setRepeatCount] = useState(2);
  const [busy, setBusy] = useState(false);
  const [lookupBusy, setLookupBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const scenarioRows = useMemo(() => getScenarioMetricRows(evaluation), [evaluation]);
  const timelineRows = useMemo(() => getStrategyTimeline(evaluation), [evaluation]);
  const overall = evaluation?.overall;
  const docsUrl = `${API_BASE_URL.replace(/\/api\/v1\/?$/, "")}/docs`;

  async function checkConnection() {
    setConnection("checking");
    try {
      const data = await getScenarios();
      setScenarios(data);
      setConnection("connected");
      return true;
    } catch {
      setConnection("disconnected");
      return false;
    }
  }

  useEffect(() => { checkConnection(); }, []);

  async function refresh() {
    setError("");
    setNotice("");
    if (evaluationId.trim()) {
      setLookupBusy(true);
      try {
        const saved = await getEvaluation(evaluationId.trim());
        setEvaluation(saved);
        setEvaluationId(saved.evaluation_id);
        setConnection("connected");
        setNotice("Evaluation refreshed from the API.");
      } catch (requestError) {
        setError(requestError.message);
        setConnection("disconnected");
      } finally {
        setLookupBusy(false);
      }
    } else {
      await checkConnection();
      setNotice("API connection checked. Enter a saved evaluation ID to load results.");
    }
  }

  async function submitEvaluation(event) {
    event.preventDefault();
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await runEvaluation({
        evaluation_id: formId.trim() || undefined,
        repetitions: Number(repetitions),
        repeated_access_count: Number(repeatCount),
      });
      setEvaluation(result);
      setEvaluationId(result.evaluation_id);
      setFormId(makeEvaluationId());
      setConnection("connected");
      setNotice(`Evaluation ${result.evaluation_id} completed with ${result.status} status.`);
    } catch (requestError) {
      setError(requestError.message);
      if (requestError.message.includes("Could not reach the API")) setConnection("disconnected");
    } finally {
      setBusy(false);
    }
  }

  async function lookupEvaluation(event) {
    event.preventDefault();
    const id = evaluationId.trim();
    if (!id) {
      setError("Enter an evaluation ID to look it up.");
      return;
    }
    if (id.length > 16 || !/^[A-Za-z0-9_-]+$/.test(id)) {
      setError("Evaluation IDs must use 1–16 letters, numbers, underscores, or hyphens.");
      return;
    }
    setLookupBusy(true);
    setError("");
    setNotice("");
    try {
      const result = await getEvaluation(id);
      setEvaluation(result);
      setEvaluationId(result.evaluation_id);
      setConnection("connected");
      setNotice(`Loaded saved evaluation ${result.evaluation_id}.`);
    } catch (requestError) {
      setError(requestError.message);
      if (requestError.message.includes("Could not reach the API")) setConnection("disconnected");
    } finally {
      setLookupBusy(false);
    }
  }

  const runValue = overall ? formatRatio(overall.completed_runs, overall.runs_requested) : "—";
  const interactionValue = overall ? formatRatio(overall.interactions_recorded, overall.interactions_attempted) : "—";

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNavOpen ? "sidebar-open" : ""}`} aria-label="Main navigation">
        <a className="brand" href="#overview" aria-label="Decentralized AI Honeypot dashboard home">
          <span className="brand-mark"><Icon name="shield" size={23} /></span>
          <span className="brand-copy"><strong>Decentralized AI</strong><small>HONEYPOT NETWORK</small></span>
        </a>
        <div className="nav-label">WORKSPACE</div>
        <nav className="nav-links">
          <a className="nav-link active" href="#overview" onClick={() => setMobileNavOpen(false)}><Icon name="chart" /><span>Evaluation overview</span></a>
          <a className="nav-link" href="#scenarios" onClick={() => setMobileNavOpen(false)}><Icon name="layers" /><span>Scenario analysis</span></a>
          <a className="nav-link" href="#runs" onClick={() => setMobileNavOpen(false)}><Icon name="runs" /><span>Run details</span></a>
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-status"><span className="mini-shield"><Icon name="shield" size={18} /></span><div><strong>Simulation mode</strong><small>Synthetic activity only</small></div></div>
          <a className="docs-link" href={docsUrl} target="_blank" rel="noreferrer">API documentation <Icon name="arrow" size={14} /></a>
        </div>
      </aside>
      {mobileNavOpen && <button className="mobile-backdrop" aria-label="Close navigation" onClick={() => setMobileNavOpen(false)} />}

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="crumb"><span>Workspace</span><b>/</b><strong>Evaluation</strong></div>
          <div className="top-actions"><StatusPill status={connection} /><button className="icon-button" onClick={refresh} disabled={lookupBusy || busy} aria-label="Refresh API connection or selected evaluation" title="Refresh"><Icon name="refresh" /></button><button className="mobile-menu" onClick={() => setMobileNavOpen((open) => !open)} aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileNavOpen}><Icon name="menu" /></button></div>
        </header>

        <div className="page-wrap">
          <section className="page-title-row">
            <div><div className="eyebrow">DEFENSIVE SYSTEM ANALYTICS</div><h1>Evaluation dashboard</h1><p>Measure scenario execution and adaptive honeypot response from recorded runs.</p></div>
            {evaluation && <div className={`evaluation-state state-${evaluation.status}`}><span className="status-dot" />{evaluation.status}<small>{new Date(evaluation.ended_at).toLocaleString()}</small></div>}
          </section>

          {error && <div className="alert alert-error" role="alert"><strong>Request failed</strong><span>{error}</span><button onClick={() => setError("")} aria-label="Dismiss error">×</button></div>}
          {notice && <div className="alert alert-success" role="status"><span>{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message">×</button></div>}

          <section className="control-grid" aria-label="Evaluation controls">
            <form className="panel launch-panel" onSubmit={submitEvaluation}>
              <div className="control-heading"><span className="control-icon"><Icon name="play" /></span><div><h2>Launch evaluation</h2><p>Run all {scenarios.length || 5} available scenarios with fresh actors.</p></div></div>
              <div className="form-row">
                <label className="field field-id"><span>Evaluation ID <small>Optional · 1–16 characters</small></span><input value={formId} onChange={(event) => setFormId(event.target.value)} maxLength={16} pattern="[A-Za-z0-9_-]+" aria-label="New evaluation ID" /></label>
                <label className="field"><span>Repetitions <small>1–20 per scenario</small></span><input type="number" min="1" max="20" value={repetitions} onChange={(event) => setRepetitions(event.target.value)} /></label>
                <label className="field"><span>Repeated access <small>Interactions · 2–5</small></span><input type="number" min="2" max="5" value={repeatCount} onChange={(event) => setRepeatCount(event.target.value)} /></label>
              </div>
              <div className="launch-footer"><span>Creates {Number(repetitions) * (scenarios.length || 5)} isolated runs</span><button type="submit" className="primary-button" disabled={busy || connection === "checking"}>{busy ? <><span className="spinner" />Running evaluation…</> : <><Icon name="play" size={15} />Run evaluation</>}</button></div>
            </form>
            <form className="panel lookup-panel" onSubmit={lookupEvaluation}>
              <div className="control-heading"><span className="control-icon secondary"><Icon name="search" /></span><div><h2>Load saved evaluation</h2><p>Look up a known ID. The API does not provide an evaluation list.</p></div></div>
              <label className="field lookup-field"><span>Evaluation ID</span><div className="input-action"><input value={evaluationId} onChange={(event) => setEvaluationId(event.target.value)} maxLength={16} placeholder="e.g. eval2210a1" aria-label="Saved evaluation ID" /><button className="secondary-button" type="submit" disabled={lookupBusy || busy}>{lookupBusy ? "Loading…" : "Load results"}</button></div></label>
              {evaluation && <div className="current-id"><span>Currently viewing</span><code>{evaluation.evaluation_id}</code></div>}
            </form>
          </section>

          {evaluation ? <>
            <section className="kpi-section" aria-label="Evaluation overview metrics">
              <div className="section-heading compact-heading"><div><span className="eyebrow">EVALUATION SUMMARY</span><h2>Overall performance</h2></div><span className="evaluation-id-chip">ID <code>{evaluation.evaluation_id}</code></span></div>
              <div className="kpi-grid">
                <KpiCard label="Runs completed" value={runValue} detail={`${formatPercent(overall.completion_rate)} completion`} icon="runs" tone="teal" />
                <KpiCard label="Interactions recorded" value={interactionValue} detail={`${formatPercent(overall.event_recording_rate)} event recording`} icon="pulse" tone="green" />
                <KpiCard label="Strategy-change rate" value={formatPercent(overall.strategy_change_rate)} detail={`${overall.strategy_changed_runs} of ${overall.strategy_measurement_runs} measured runs`} icon="chart" tone="blue" />
                <KpiCard label="Decoys generated" value={overall.decoys_generated.toLocaleString()} detail={`${formatPercent(overall.decoy_generation_rate)} of measured runs`} icon="layers" tone="teal" />
                <KpiCard label="Errors" value={overall.errors.toLocaleString()} detail={`${overall.incomplete_runs} incomplete · ${overall.failed_runs} failed runs`} icon="pulse" tone={overall.errors ? "amber" : "green"} />
                <KpiCard label="Median latency" value={formatLatency(overall.median_latency_ms)} detail={`${overall.latency_sample_count} measured runs`} icon="chart" tone="blue" />
                <KpiCard label="p95 latency" value={formatLatency(overall.p95_latency_ms)} detail={`Requires ${overall.p95_minimum_sample_size}+ samples`} icon="chart" tone="amber" />
                <KpiCard label="Evaluation duration" value={`${(evaluation.elapsed_seconds * 1000).toFixed(0)} ms`} detail={`${evaluation.repetitions_per_scenario} repetitions per scenario`} icon="pulse" tone="green" />
              </div>
            </section>

            <section className="charts-section" id="scenarios">
              <div className="section-heading"><div><span className="eyebrow">COMPARATIVE ANALYSIS</span><h2>Scenario comparison</h2><p>Each chart uses the selected evaluation’s per-scenario aggregate.</p></div></div>
              <div className="chart-grid">
                <ScenarioChart title="Completion rate" subtitle="Fully recorded runs / requested" rows={scenarioRows} metric="completionRate" unit="%" color="#49d2c2" maxValue={1} />
                <ScenarioChart title="Event recording" subtitle="Recorded interactions / attempted" rows={scenarioRows} metric="eventRecordingRate" unit="%" color="#61c995" maxValue={1} />
                <ScenarioChart title="Strategy changes" subtitle="Runs with a measured transition" rows={scenarioRows} metric="strategyChangeRate" unit="%" color="#76a9e8" maxValue={1} />
                <ScenarioChart title="Generated decoys" subtitle="New registry entries attributed to runs" rows={scenarioRows} metric="decoysGenerated" unit="count" color="#43bcb0" />
                <ScenarioChart title="Median latency" subtitle="Simulation run duration · milliseconds" rows={scenarioRows} metric="medianLatencyMs" unit="ms" color="#c2a0ed" />
                <article className="panel quality-panel"><div className="panel-heading"><div><h3>Measurement notes</h3><p>Limitations reported by the evaluation API.</p></div><span className="note-mark">i</span></div><ul>{evaluation.unavailable_measurements.map((item) => <li key={item}>{item}</li>)}</ul></article>
              </div>
            </section>

            <div className="results-grid">
              <StrategyTimeline evaluation={evaluation} />
              <section className="panel quality-callout"><span className="callout-icon"><Icon name="shield" /></span><div><h3>Measured behavior only</h3><p>Expected action sequence matches compare recorded actions with the scenario’s defined steps. This is scenario conformance, not a classifier accuracy score.</p><div className="callout-stats"><span>{evaluation.overall.runs_with_summary} runs with summaries</span><span>{evaluation.overall.strategy_measurement_runs} strategy measurements</span></div></div></section>
            </div>

            <div className="detail-sections" id="runs">
              <ScenarioTable evaluation={evaluation} />
              <RunDetails evaluation={evaluation} />
            </div>
          </> : <>
            <section className="empty-dashboard panel"><span className="empty-symbol large"><Icon name="chart" size={25} /></span><span className="eyebrow">READY WHEN YOU ARE</span><h2>No evaluation selected</h2><p>Launch an evaluation or look up a saved evaluation ID. Metrics and scenario charts will appear here from the API response.</p><div className="empty-features"><span><Icon name="shield" size={16} />Synthetic scenarios</span><span><Icon name="pulse" size={16} />Recorded measurements</span><span><Icon name="layers" size={16} />Adaptive decoy response</span></div></section>
            <div className="charts-section initial-charts"><div className="section-heading"><div><span className="eyebrow">SCENARIO COMPARISON</span><h2>Five deterministic scenarios</h2></div></div><div className="chart-grid">
              <ScenarioChart title="Completion rate" subtitle="Fully recorded runs / requested" rows={[]} metric="completionRate" unit="%" color="#49d2c2" maxValue={1} />
              <ScenarioChart title="Event recording" subtitle="Recorded interactions / attempted" rows={[]} metric="eventRecordingRate" unit="%" color="#61c995" maxValue={1} />
            </div></div>
          </>}
          <footer className="page-footer"><span>Decentralized AI Honeypot</span><span>Evaluation data is loaded from the configured API.</span><span>{evaluation ? `Updated ${new Date(evaluation.ended_at).toLocaleTimeString()}` : "No evaluation loaded"}</span></footer>
        </div>
      </main>
    </div>
  );
}
