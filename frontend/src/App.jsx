import { useEffect, useMemo, useState } from "react";
import { API_BASE_URL, getAdminSession, loginAdmin, logoutAdmin, getNetworkNodeDashboard, getEvaluation, getScenarios, getTelemetryAlerts, getCowrieEvents, getIncidents, getIncidentStats, updateIncident, openTelemetryStream, runEvaluation, getBehaviorProfiles, getProfileStats, recomputeProfiles, getDeceptionRecommendations, evaluateDeceptionRecommendation, approveDeceptionRecommendation, runExperiment, getExperiments, getExperiment, downloadExperimentReport, getPublicDemo } from "./api.js";
import { publicDemoMetrics } from "./public-demo.js";
import InteractiveSandbox from "./InteractiveSandbox.jsx";
import "./sandbox.css";
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

function PolicyModeComparison({ modes }) {
  return (
    <section className="policy-comparison-section" aria-label="Baseline and behavior-conditioned comparison">
      <div className="section-heading">
        <div><span className="eyebrow">POLICY COMPARISON</span><h2>Baseline vs behavior-conditioned</h2><p>Each policy uses fresh actors and simulation IDs. These synthetic runs measure workflow behavior, not real-world defense effectiveness.</p></div>
      </div>
      <div className="policy-comparison-grid">
        {modes.map((mode) => (
          <article className="panel policy-mode-card" key={mode.policy_mode}>
            <div className="policy-mode-title"><h3>{mode.policy_mode.replaceAll("_", " ")}</h3><span>{mode.completed_runs} / {mode.runs_requested} completed</span></div>
            <dl className="policy-mode-metrics">
              <div><dt>Completion</dt><dd>{formatPercent(mode.completion_rate)}</dd></div>
              <div><dt>Strategy changes</dt><dd>{formatRatio(mode.strategy_changed_runs, mode.strategy_measurement_runs)}</dd></div>
              <div><dt>Decoys generated</dt><dd>{mode.decoys_generated.toLocaleString()}</dd></div>
              <div><dt>Validated bundles</dt><dd>{mode.validated_bundles ?? 0} / {mode.bundles_generated ?? 0}</dd></div>
              <div><dt>Median latency</dt><dd>{formatLatency(mode.median_latency_ms)}</dd></div>
              <div><dt>Errors</dt><dd>{mode.errors.toLocaleString()}</dd></div>
              <div className="policy-categories"><dt>Generated categories</dt><dd>{Object.entries(mode.generated_decoy_categories || {}).map(([category, count]) => `${category}: ${count}`).join(" · ") || "None"}</dd></div>
            </dl>
          </article>
        ))}
      </div>
    </section>
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
              <div className="detail-wide"><dt>Bundle IDs</dt><dd className="mono">{summary?.bundle_ids?.join(", ") || "None"}</dd></div>
              <div><dt>Bundle assets</dt><dd>{Object.entries(summary?.bundle_asset_categories || {}).map(([category, count]) => `${category}: ${count}`).join(" · ") || "None"}</dd></div>
              <div><dt>Bundle validation</dt><dd>{summary?.bundle_validation_results?.length ? summary.bundle_validation_results.map((result) => `${result.bundle_id}: ${result.valid ? "valid" : "invalid"}`).join(" · ") : "None"}</dd></div>
              {run.execution_error && <div className="detail-wide"><dt>Execution error</dt><dd className="error-copy">{run.execution_error}</dd></div>}
              {!!summary?.errors?.length && <div className="detail-wide"><dt>Interaction errors</dt><dd className="error-copy">{summary.errors.map((error) => `Step ${error.step}: ${error.message}`).join(" · ")}</dd></div>}
            </dl>
          </div>
        </details>;
      })}</div>}
    </section>
  );
}

function LiveTelemetryPanel({ events, alerts, status }) {
  const statusLabel = status === "connected" ? "Live" : status === "reconnecting" ? "Reconnecting" : "Connecting";
  return (
    <section className="panel live-telemetry-panel" aria-label="Live telemetry and alerts">
      <div className="section-heading">
        <div><span className="eyebrow">LIVE SECURITY FEED</span><h2>Telemetry &amp; alerts</h2><p>Normalized event summaries update while the dashboard is open.</p></div>
        <span className={`live-status live-${status}`}><span className="status-dot" />{statusLabel}</span>
      </div>
      <div className="live-feed-grid">
        <div className="live-feed-column">
          <h3>Recent events <span>{events.length}</span></h3>
          {events.length === 0 ? <p className="live-empty">Waiting for recorded events.</p> : <ul className="live-event-list">
            {events.map((event) => <li key={event.event_id}>
              <span className={`severity-dot severity-${event.severity}`} />
              <div><strong>{event.telemetry_event_type || event.action}</strong><small>{event.source_system || event.source} · {new Date(event.timestamp).toLocaleTimeString()}</small></div>
              <span className="live-severity">{event.severity}</span>
            </li>)}
          </ul>}
        </div>
        <div className="live-feed-column alert-feed-column">
          <h3>Suspicious activity <span>{alerts.length}</span></h3>
          {alerts.length === 0 ? <p className="live-empty">No rule-based alerts in the current feed.</p> : <ul className="live-event-list">
            {alerts.map((alert) => <li key={alert.alert_id}>
              <span className={`severity-dot severity-${alert.severity}`} />
              <div><strong>{alert.event_type}</strong><small>{alert.message}</small></div>
              <span className="live-severity">{alert.severity}</span>
            </li>)}
          </ul>}
        </div>
      </div>
    </section>
  );
}

function IncidentPanel({ data, loading, error, onAction }) {
  return (
    <section className="panel incident-panel" aria-label="Correlated security incidents">
      <div className="section-heading"><div><span className="eyebrow">CROSS-SOURCE CORRELATION</span><h2>Incidents</h2><p>Rule-based correlations of Zeek and Suricata events. Confidence describes rule evidence, not probability of compromise.</p></div><span className="incident-total">{data.total} tracked</span></div>
      <div className="incident-counts" aria-label="Incident status counts">{["open", "acknowledged", "resolved"].map((status) => <span key={status}><strong>{data.statusCounts[status]}</strong>{status}</span>)}</div>
      <div className="incident-counts incident-severity-counts" aria-label="Incident severity breakdown">{["critical", "high", "medium", "low"].map((severity) => <span key={severity}><strong>{data.severityCounts[severity] || 0}</strong>{severity}</span>)}</div>
      {error && <p className="incident-error" role="alert">Could not load incidents: {error}</p>}
      {loading ? <p className="live-empty">Loading incident data…</p> : data.incidents.length === 0 ? <p className="live-empty">No correlated incidents are recorded.</p> : <ul className="incident-list">{data.incidents.map((incident) => <li key={incident.id} className="incident-item">
        <div className="incident-main"><span className={`severity-dot severity-${incident.severity}`} /><div><strong>{incident.sourceIp} · {incident.severity}</strong><small>{incident.status} · {Math.round(incident.confidence * 100)}% rule evidence · {new Date(incident.lastSeen).toLocaleString()}</small></div></div>
        <ul className="incident-evidence">{incident.evidence.map((text) => <li key={text}>{text}</li>)}</ul>
        <div className="incident-tags">{incident.rules.map((rule) => <code key={rule}>{rule}</code>)}{incident.sensors.map((sensor) => <span key={sensor}>{sensor}</span>)}</div>
        {incident.status !== "resolved" && <div className="incident-actions">{incident.status === "open" && <button className="secondary-button" onClick={() => onAction(incident.id, "acknowledge")}>Acknowledge</button>}<button className="secondary-button" onClick={() => onAction(incident.id, "resolve")}>Resolve</button></div>}
      </li>)}</ul>}
    </section>
  );
}

function CowrieActivityPanel({ events, loading, error }) {
  const data = getCowrieDashboardData(events);
  return (
    <section className="panel cowrie-panel" aria-label="Cowrie SSH honeypot activity">
      <div className="section-heading"><div><span className="eyebrow">SSH HONEYPOT SENSOR</span><h2>Cowrie activity</h2><p>Recent sanitized telemetry only. Passwords, command text/output, filenames, and file contents are withheld.</p></div><span className="incident-total">Recent {events.length}</span></div>
      <div className="incident-counts" aria-label="Cowrie activity counts">
        <span><strong>{data.authenticationFailures}</strong>failed logins</span>
        <span><strong>{data.authenticationSuccesses}</strong>successful logins</span>
        <span><strong>{data.sessionEvents}</strong>session events</span>
        <span><strong>{data.commandAttempts}</strong>command attempts</span>
      </div>
      {error && <p className="incident-error" role="alert">Could not load Cowrie events: {error}</p>}
      {loading ? <p className="live-empty">Loading Cowrie activity…</p> : data.records.length === 0 ? <p className="live-empty">No Cowrie events have been ingested.</p> : <ul className="incident-list">{data.records.map((record) => <li key={record.id} className="incident-item">
        <div className="incident-main"><span className={`severity-dot severity-${events.find((event) => event.event_id === record.id)?.severity || "low"}`} /><div><strong>{record.summary}</strong><small>{record.sourceIp} · {new Date(record.timestamp).toLocaleString()}</small></div></div>
        <div className="incident-tags"><code>{record.type}</code>{record.authOutcome && <span>authentication: {record.authOutcome}</span>}{record.sessionRef !== "Unavailable" && <span>session ref {record.sessionRef}</span>}</div>
      </li>)}</ul>}
    </section>
  );
}

function AttackerProfilesPanel() {
  const [profiles, setProfiles] = useState([]);
  const [stats, setStats] = useState(null);
  const [recommendations, setRecommendations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const data = getProfileDashboardData(profiles, stats, recommendations);

  async function refresh() {
    setLoading(true);
    setError("");
    try {
      const [profilePage, profileStats, recommendationPage] = await Promise.all([
        getBehaviorProfiles({ limit: 50 }), getProfileStats(), getDeceptionRecommendations({ limit: 50 }),
      ]);
      setProfiles(profilePage.items || []);
      setStats(profileStats);
      setRecommendations(recommendationPage.items || []);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { refresh(); }, []);

  async function recompute() {
    setBusy("recompute");
    setNotice("");
    setError("");
    try {
      const result = await recomputeProfiles(3600);
      setNotice(`Recomputed ${result.profiles_updated} profiles; ${result.recommendations_created} new recommendations. Model ${result.model_version}.`);
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy("");
    }
  }

  async function reviewAction(recommendation, action) {
    setBusy(`${action}:${recommendation.id}`);
    setError("");
    setNotice("");
    try {
      const updated = action === "evaluate"
        ? await evaluateDeceptionRecommendation(recommendation.id)
        : await approveDeceptionRecommendation(recommendation.id);
      setRecommendations((current) => current.map((item) => item.recommendation_id === updated.recommendation_id ? updated : item));
      setNotice(action === "approve" ? "Recommendation approved for review; no deployment or enforcement occurred." : `Local synthetic evaluation ${updated.evaluation?.outcome || "completed"}.`);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setBusy("");
    }
  }

  const categoryMax = Math.max(1, ...Object.values(data.categoryCounts).map((value) => Number(value) || 0));
  const clusterMax = Math.max(1, ...Object.values(data.clusterCounts).map((value) => Number(value) || 0));
  return (
    <section className="panel behavior-panel" id="profiles" aria-label="Attacker behavior profiles and deception recommendations">
      <div className="section-heading"><div><span className="eyebrow">TELEMETRY BEHAVIOR MODELS</span><h2>Attacker behavior profiles</h2><p>Aggregate-only profiles; categories are model outputs from synthetic training labels, not confirmed intent.</p></div><button className="secondary-button" onClick={recompute} disabled={busy !== ""}>{busy === "recompute" ? "Recomputing…" : "Recompute profiles"}</button></div>
      {error && <p className="incident-error" role="alert">{error}</p>}
      {notice && <p className="profile-notice" role="status">{notice}</p>}
      <div className="profile-summary-grid">
        <article><span>Profiles</span><strong>{data.totalProfiles}</strong></article>
        <article><span>Mean anomaly index</span><strong>{data.meanAnomalyIndex === null ? "Unavailable" : data.meanAnomalyIndex.toFixed(3)}</strong></article>
        <article><span>Cluster groups</span><strong>{Object.keys(data.clusterCounts).length}</strong></article>
        <article><span>Model version</span><strong className="profile-version">{data.modelVersion || "Unavailable"}</strong></article>
      </div>
      <p className="profile-note">Anomaly index is relative to a synthetic baseline, not a probability. Train the local model before recomputing profiles.</p>
      <div className="profile-distributions">
        <div><h3>Behavior categories</h3>{Object.keys(data.categoryCounts).length ? Object.entries(data.categoryCounts).map(([label, count]) => <div className="profile-bar-row" key={label}><span>{label.replaceAll("_", " ")}</span><div><i style={{ width: `${Math.max(4, (count / categoryMax) * 100)}%` }} /></div><b>{count}</b></div>) : <p className="live-empty">Unavailable until profiles are recomputed.</p>}</div>
        <div><h3>Cluster distribution</h3>{Object.keys(data.clusterCounts).length ? Object.entries(data.clusterCounts).sort(([a], [b]) => Number(a) - Number(b)).map(([label, count]) => <div className="profile-bar-row" key={label}><span>Cluster {label}</span><div><i className="cluster-bar" style={{ width: `${Math.max(4, (count / clusterMax) * 100)}%` }} /></div><b>{count}</b></div>) : <p className="live-empty">Unavailable until profiles are recomputed.</p>}</div>
      </div>
      <div className="profile-section-heading"><h3>Profile details</h3><span>{loading ? "Loading…" : `${data.profiles.length} shown`}</span></div>
      {loading ? <p className="live-empty">Loading profiles…</p> : data.profiles.length === 0 ? <p className="live-empty">No external sensor profiles yet. Ingest Zeek, Suricata, or Cowrie telemetry, train the synthetic model, then recompute.</p> : <div className="profile-list">{data.profiles.map((profile) => <details className="profile-card" key={profile.id}><summary><span><strong>{profile.category.replaceAll("_", " ")}</strong><small>{profile.sourceRef.slice(0, 16)}… · {profile.observations} observations · cluster {profile.cluster ?? "Unavailable"}</small></span><span className="anomaly-meter"><b>{profile.anomalyIndex === null ? "Unavailable" : profile.anomalyIndex.toFixed(2)}</b><i style={{ width: profile.anomalyIndex === null ? "0%" : `${profile.anomalyIndex * 100}%` }} /></span></summary><div className="profile-card-body"><p>Observed {new Date(profile.firstObserved).toLocaleString()} to {new Date(profile.lastObserved).toLocaleString()} · model {profile.modelVersion}</p><div className="feature-chip-list">{Object.entries(profile.features).filter(([, value]) => value !== 0).slice(0, 12).map(([name, value]) => <span key={name}>{name.replaceAll("_", " ")}: <b>{typeof value === "number" ? Number(value.toFixed?.(3) ?? value) : value}</b></span>)}</div><small>Feature importance is global to the synthetic classifier; it is explanatory context, not a per-event causal attribution.</small><ol>{profile.history.map((item, index) => <li key={`${profile.id}-${index}`}>{item.category.replaceAll("_", " ")} · {new Date(item.recorded_at).toLocaleString()}{item.changes?.length ? ` · ${item.changes.join(", ")}` : ""}</li>)}</ol></div></details>)}</div>}
      <div className="profile-section-heading"><h3>Adaptive deception recommendations</h3><span>Explicit review required</span></div>
      {loading ? <p className="live-empty">Loading recommendations…</p> : data.recommendations.length === 0 ? <p className="live-empty">Recommendations will appear after profile recomputation.</p> : <div className="recommendation-list">{data.recommendations.map((item) => <article className="recommendation-card" key={item.id}><div className="recommendation-head"><div><span className="eyebrow">{item.category.replaceAll("_", " ")}</span><h4>{item.title}</h4></div><span className={`recommendation-state state-${item.status}`}>{item.status.replaceAll("_", " ")}</span></div><p>{item.rationale}</p><div className="recommendation-meta"><span>Strategy: <code>{item.strategy}</code></span><span>Scenario: {item.expectedScenario || "More evidence required"}</span></div>{item.evaluation && <div className="evaluation-evidence"><strong>Local evaluation: {item.evaluation.outcome}</strong><span>Scenarios: {item.evaluation.measured_scenarios.join(", ") || "Unavailable"}</span><span>Interactions: {item.evaluation.interactions_recorded ?? "Unavailable"} / {item.evaluation.interactions_attempted ?? "Unavailable"}</span><span>Decoys generated: {item.evaluation.generated_decoys ?? "Unavailable"} · duration: {item.evaluation.elapsed_seconds === null ? "Unavailable" : `${(item.evaluation.elapsed_seconds * 1000).toFixed(1)} ms`}</span><small>{item.evaluation.telemetry_coverage} {item.evaluation.false_positive_risk}</small></div>}<div className="recommendation-actions">{item.status !== "approved" && <button className="secondary-button" onClick={() => reviewAction(item, "evaluate")} disabled={busy !== ""}>{busy === `evaluate:${item.id}` ? "Evaluating…" : item.status === "evaluation_failed" ? "Retry evaluation" : "Evaluate locally"}</button>}{item.status === "evaluated" && item.evaluation?.outcome === "passed" && <button className="primary-button" onClick={() => reviewAction(item, "approve")} disabled={busy !== ""}>{busy === `approve:${item.id}` ? "Approving…" : "Approve recommendation"}</button>}</div><small className="recommendation-warning">Approval records workflow state only. It does not deploy a decoy, expose a service, execute commands, or block traffic.</small></article>)}</div>}
    </section>
  );
}

const EXPERIMENT_SCENARIOS = ["reconnaissance", "ssh_authentication_probing", "repeated_failed_authentication", "successful_auth_suspicious_activity", "multi_port_probing", "multi_protocol_activity", "repeated_session_behavior", "multi_sensor_correlated_activity", "low_and_slow_activity", "mixed_benign_suspicious_traffic"];

function ExperimentsPanel() {
  const [scenarios, setScenarios] = useState([...EXPERIMENT_SCENARIOS]);
  const [modes, setModes] = useState(["baseline", "adaptive"]);
  const [repetitions, setRepetitions] = useState(1);
  const [seed, setSeed] = useState(2026);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    getExperiments().then((data) => active && setHistory(data.items || [])).catch((e) => active && setError(e.message));
    return () => { active = false; };
  }, []);
  const view = getExperimentDashboardData(result);
  const load = async (id) => {
    setLoading(true); setError("");
    try { const item = await getExperiment(id); setResult(item); }
    catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };
  const submit = async (event) => {
    event.preventDefault();
    if (!scenarios.length || !modes.length) { setError("Select at least one scenario and one mode."); return; }
    setBusy(true); setError("");
    try {
      const item = await runExperiment({ scenarios, modes, repetitions: Number(repetitions), seed: Number(seed) });
      setResult(item);
      const latest = await getExperiments(); setHistory(latest.items || []);
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };
  const toggle = (values, setValues, value) => setValues(values.includes(value) ? values.filter((item) => item !== value) : [...values, value]);
  return <section className="panel experiment-panel" id="experiments" aria-label="Offline adversary experiments">
    <div className="section-heading"><div><span className="eyebrow">OFFLINE SYNTHETIC EVALUATION</span><h2>Adversary experiments</h2><p>Paired runs use deterministic synthetic events. The optional closed-loop mode simulates attacker reactions and updates a policy local to this experiment; no network connections or live policy changes occur.</p></div></div>
    {error && <p className="incident-error" role="alert">{error}</p>}
    <form className="experiment-form" onSubmit={submit}>
      <div className="experiment-config-row"><label className="field"><span>Repetitions per scenario (1–10)</span><input type="number" min="1" max="10" value={repetitions} onChange={(e) => setRepetitions(e.target.value)} /></label><label className="field"><span>Random seed</span><input type="number" min="0" max="4294967295" value={seed} onChange={(e) => setSeed(e.target.value)} /></label><div className="experiment-options"><strong>Modes</strong>{["baseline", "adaptive", "closed_loop"].map((mode) => <label key={mode}><input type="checkbox" checked={modes.includes(mode)} onChange={() => toggle(modes, setModes, mode)} />{mode.replaceAll("_", " ")}</label>)}</div></div>
      <fieldset className="experiment-scenarios"><legend>Scenarios ({scenarios.length} selected; max 200 mode-runs)</legend>{EXPERIMENT_SCENARIOS.map((scenario) => <label key={scenario}><input type="checkbox" checked={scenarios.includes(scenario)} onChange={() => toggle(scenarios, setScenarios, scenario)} />{scenario.replaceAll("_", " ")}</label>)}</fieldset>
      <button className="primary-button" disabled={busy || loading}>{busy ? "Running synthetic experiment…" : "Run experiment"}</button>
    </form>
    <div className="experiment-history"><strong>Saved experiments</strong>{history.length ? history.slice(0, 10).map((item) => <button type="button" key={item.experiment_id} className="secondary-button" onClick={() => load(item.experiment_id)}>{item.experiment_id} · seed {item.seed}</button>) : <span>{loading ? "Loading…" : "No saved experiments yet."}</span>}</div>
    {result && <div className="experiment-results"><div className="section-heading"><div><span className="eyebrow">{result.experiment_id} · SEED {result.seed}</span><h3>Measured results</h3></div><div className="experiment-downloads">{["json", "csv", "markdown"].map((format) => <button type="button" className="secondary-button" key={format} onClick={async () => { try { await downloadExperimentReport(result.experiment_id, format); } catch (downloadError) { setError(downloadError.message); } }}>{format.toUpperCase()} report</button>)}</div></div>
      <div className="experiment-mode-grid">{view.modeRows.map((row) => <article key={row.mode}><h4>{row.mode.replaceAll("_", " ")}</h4><span>Detection coverage <b>{formatPercent(row.coverage)}</b></span><span>Event capture <b>{formatPercent(row.capture)}</b></span><span>Incident detection <b>{formatPercent(row.incidentRate)}</b></span><span>False positive / negative <b>{formatPercent(row.falsePositive)} / {formatPercent(row.falseNegative)}</b></span><span>Completion <b>{formatPercent(row.completion)}</b></span><span>Strategy changes <b>{row.adaptations}</b></span><span>Simulated engagement <b>{formatPercent(row.simulatedEngagement)}</b></span><span>Synthetic interaction depth <b>{Number.isFinite(row.meanSyntheticDepth) ? row.meanSyntheticDepth.toFixed(2) : "Unavailable"}</b></span><span>Virtual session duration <b>{Number.isFinite(row.medianSyntheticDuration) ? `${row.medianSyntheticDuration.toFixed(1)} s` : "Unavailable"}</b></span><span>Unique decoys accessed <b>{row.uniqueDecoysAccessed ?? "Unavailable"}</b></span>{row.meanReward != null && <span>Mean synthetic reward <b>{row.meanReward.toFixed(3)}</b></span>}</article>)}</div>
      <div className="experiment-chart-grid" aria-label="Baseline, adaptive, and closed-loop metric comparison">{["detection_coverage", "event_capture_rate", "incident_detection_rate", "false_positive_rate", "false_negative_rate"].map((metric) => { const values = view.modeRows.map((row) => ({ mode: row.mode, value: ({ detection_coverage: row.coverage, event_capture_rate: row.capture, incident_detection_rate: row.incidentRate, false_positive_rate: row.falsePositive, false_negative_rate: row.falseNegative })[metric] })); return <div key={metric}><strong>{metric.replaceAll("_", " ")}</strong>{values.map((item) => <span key={item.mode}>{item.mode.replaceAll("_", " ")}<i className={`experiment-bar ${item.mode}`}><b style={{ width: Number.isFinite(item.value) ? `${Math.max(0, Math.min(100, item.value * 100))}%` : "0%" }} /></i><em>{formatPercent(item.value)}</em></span>)}</div>; })}</div>
      <div className="experiment-table-wrap"><table><thead><tr><th>Metric</th><th>Baseline</th><th>Adaptive</th><th>Closed loop</th><th>Adaptive difference</th></tr></thead><tbody>{view.comparisonRows.map((row) => <tr key={row.metric}><td>{row.metric.replaceAll("_", " ")}</td><td>{row.baseline ?? "Unavailable"}</td><td>{row.adaptive ?? "Unavailable"}</td><td>{row.closed_loop ?? "Not selected"}</td><td>{row.absolute_difference ?? "Unavailable"}</td></tr>)}</tbody></table></div>
      <h4>Scenario results and adaptation history</h4><div className="experiment-table-wrap"><table><thead><tr><th>Scenario</th><th>Mode</th><th>Detection</th><th>FP</th><th>FN</th><th>Latency</th><th>Strategy / reason</th><th>Reaction / reward</th></tr></thead><tbody>{view.scenarioRows.map((row, i) => <tr key={`${row.scenario}-${row.repetition}-${row.mode}-${i}`}><td>{row.scenario.replaceAll("_", " ")}</td><td>{row.mode.replaceAll("_", " ")}</td><td>{row.true_positives}</td><td>{row.false_positives}</td><td>{row.false_negatives}</td><td>{row.detection_latency_seconds ?? "Unavailable"}</td><td>{row.selected_strategy}{row.adaptation_reason && <small>{row.adaptation_reason}</small>}</td><td>{row.attacker_reactions?.join(", ") || "—"}{row.strategy_reward != null && <small>Reward: {row.strategy_reward.toFixed(3)}</small>}</td></tr>)}</tbody></table></div>
      <p className="profile-note">{result.limitations.join(" ")}</p>
    </div>}
  </section>;
}

function NetworkOperationsPanel() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const result = await getNetworkNodeDashboard();
        if (active) { setData(result); setError(""); }
      } catch (requestError) {
        if (active) setError(requestError.message);
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
    const timer = setInterval(load, 15000);
    return () => { active = false; clearInterval(timer); };
  }, []);
  const intelligence = data?.intelligence;
  return <section className="panel network-operations-panel" id="network-ops" aria-label="Network operations dashboard">
    <div className="section-heading"><div><span className="eyebrow">NODE OPERATIONS</span><h2>Peer and intelligence status</h2><p>Read-only local node view. Adaptive performance remains in the measured experiments panel below.</p></div><span className={`network-node-state ${data?.node?.status || (loading ? "checking" : "not-configured")}`}>{data?.node?.node_id || (loading ? "Connecting" : "Node not configured")}</span></div>
    {error ? <p className="network-dashboard-error" role="status">Node dashboard unavailable: {error}</p>
        : loading && !data ? <p className="network-dashboard-note">Loading node status…</p>
          : data && <>
            <div className="network-kpis">
              <div><span>Peers configured</span><strong>{data.peers.length}</strong></div>
              <div><span>Pending intelligence</span><strong>{intelligence.pending_count}</strong></div>
              <div><span>Approved / rejected</span><strong>{intelligence.approved_count} / {intelligence.rejected_count}</strong></div>
              <div><span>Sync failures</span><strong>{data.sync_failures}</strong></div>
            </div>
            <div className="network-tables">
              <div><h3>Peer registry</h3>{data.peers.length ? <ul>{data.peers.map((peer) => <li key={peer.peer_id}><span><strong>{peer.peer_id}</strong><small>Last seen: {peer.last_seen ? new Date(peer.last_seen).toLocaleString() : "Never"} · failures: {peer.failure_count}</small></span><b className={`peer-status peer-${peer.enabled ? peer.status : "disabled"}`}>{peer.enabled ? peer.status : "disabled"}</b></li>)}</ul> : <p>No configured peers.</p>}</div>
              <div><h3>Shared intelligence</h3>{intelligence.records.length ? <ul>{intelligence.records.slice(0, 8).map((record) => <li key={record.record_id}><span><strong>{record.indicator} · {record.classification}</strong><small>{record.publisher_id} · {record.source_system} · confidence heuristic {record.confidence_score.toFixed(2)}</small></span><b className={`peer-status peer-${record.state}`}>{record.state}</b></li>)}</ul> : <p>No intelligence records.</p>}</div>
            </div>
            <small className="network-dashboard-note">{data.confidence_definition} Signatures prove key possession and integrity, not that an indicator is true.</small>
          </>}
  </section>;
}

function AuthenticatedApp({ onLogout, role }) {
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
  const [liveEvents, setLiveEvents] = useState([]);
  const [liveAlerts, setLiveAlerts] = useState([]);
  const [liveStatus, setLiveStatus] = useState("connecting");
  const [incidentPage, setIncidentPage] = useState(null);
  const [incidentStats, setIncidentStats] = useState(null);
  const [incidentLoading, setIncidentLoading] = useState(true);
  const [incidentError, setIncidentError] = useState("");
  const [cowrieEvents, setCowrieEvents] = useState([]);
  const [cowrieLoading, setCowrieLoading] = useState(true);
  const [cowrieError, setCowrieError] = useState("");
  const scenarioRows = useMemo(() => getScenarioMetricRows(evaluation), [evaluation]);
  const timelineRows = useMemo(() => getStrategyTimeline(evaluation), [evaluation]);
  const overall = evaluation?.overall;
  const docsUrl = `${API_BASE_URL.replace(/\/api\/v1\/?$/, "")}/docs`;

  async function refreshIncidents() {
    setIncidentLoading(true);
    setIncidentError("");
    try {
      const [page, stats] = await Promise.all([getIncidents(), getIncidentStats()]);
      setIncidentPage(page);
      setIncidentStats(stats);
    } catch (requestError) {
      setIncidentError(requestError.message);
    } finally {
      setIncidentLoading(false);
    }
  }

  async function actOnIncident(incidentId, action) {
    setIncidentError("");
    try {
      await updateIncident(incidentId, action);
      await refreshIncidents();
    } catch (requestError) {
      setIncidentError(requestError.message);
    }
  }

  async function refreshCowrie() {
    setCowrieError("");
    try {
      setCowrieEvents(await getCowrieEvents());
    } catch (requestError) {
      setCowrieError(requestError.message);
    } finally {
      setCowrieLoading(false);
    }
  }

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

  useEffect(() => { refreshIncidents(); }, []);
  useEffect(() => { refreshCowrie(); }, []);

  useEffect(() => {
    let mounted = true;
    getTelemetryAlerts().then((alerts) => {
      if (mounted) setLiveAlerts(alerts);
    }).catch(() => {});
    const stream = openTelemetryStream({
      onEvent: (event) => {
        if (!mounted) return;
        setLiveEvents((current) => prependUnique(current, event, "event_id"));
      },
      onAlert: (alert) => mounted && setLiveAlerts((current) => prependUnique(current, alert, "alert_id")),
      onIncident: () => mounted && refreshIncidents(),
      onCowrie: (event) => mounted && setCowrieEvents((current) => prependUnique(current, event, "event_id", 30)),
      onStatus: (status) => mounted && setLiveStatus(status),
    });
    return () => {
      mounted = false;
      stream.close();
    };
  }, []);

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
          <a className="nav-link" href="#profiles" onClick={() => setMobileNavOpen(false)}><Icon name="shield" /><span>Attacker profiles</span></a>
          <a className="nav-link" href="#network-ops" onClick={() => setMobileNavOpen(false)}><Icon name="layers" /><span>Network operations</span></a>
          <a className="nav-link" href="#experiments" onClick={() => setMobileNavOpen(false)}><Icon name="pulse" /><span>Experiments</span></a>
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
          <div className="top-actions"><StatusPill status={connection} />{role === "development" && <span className="auth-mode-label">Open dev mode</span>}{onLogout && <button className="secondary-button session-logout" onClick={onLogout}>Sign out</button>}<button className="icon-button" onClick={refresh} disabled={lookupBusy || busy} aria-label="Refresh API connection or selected evaluation" title="Refresh"><Icon name="refresh" /></button><button className="mobile-menu" onClick={() => setMobileNavOpen((open) => !open)} aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"} aria-expanded={mobileNavOpen}><Icon name="menu" /></button></div>
        </header>

        <div className="page-wrap">
          <section className="page-title-row">
            <div><div className="eyebrow">DEFENSIVE SYSTEM ANALYTICS</div><h1>Evaluation dashboard</h1><p>Measure scenario execution and adaptive honeypot response from recorded runs.</p></div>
            {evaluation && <div className={`evaluation-state state-${evaluation.status}`}><span className="status-dot" />{evaluation.status}<small>{new Date(evaluation.ended_at).toLocaleString()}</small></div>}
          </section>

          {error && <div className="alert alert-error" role="alert"><strong>Request failed</strong><span>{error}</span><button onClick={() => setError("")} aria-label="Dismiss error">×</button></div>}
          {notice && <div className="alert alert-success" role="status"><span>{notice}</span><button onClick={() => setNotice("")} aria-label="Dismiss message">×</button></div>}

          <LiveTelemetryPanel events={liveEvents} alerts={liveAlerts} status={liveStatus} />
          <NetworkOperationsPanel />
          <CowrieActivityPanel events={cowrieEvents} loading={cowrieLoading} error={cowrieError} />
          <IncidentPanel data={getIncidentDashboardData(incidentPage, incidentStats)} loading={incidentLoading} error={incidentError} onAction={actOnIncident} />
          <AttackerProfilesPanel />
          <ExperimentsPanel />

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

            {evaluation.policy_mode_metrics?.length > 0 && <PolicyModeComparison modes={evaluation.policy_mode_metrics} />}

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

export function PublicDemoDashboard({ initialSnapshot = null } = {}) {
  const [snapshot, setSnapshot] = useState(initialSnapshot);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(initialSnapshot === null);
  const [activeNav, setActiveNav] = useState("overview");

  async function load() {
    setLoading(true);
    setError("");
    try {
      setSnapshot(await getPublicDemo());
    } catch (loadError) {
      setError(loadError.message || "The demo service is waking up. Try again shortly.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  useEffect(() => {
    const syncActiveNav = () => setActiveNav(window.location.hash.slice(1) || "overview");
    syncActiveNav();
    window.addEventListener("hashchange", syncActiveNav);
    return () => window.removeEventListener("hashchange", syncActiveNav);
  }, []);

  return <div className="app-shell public-demo-app">
    <aside className="sidebar" aria-label="Public demo navigation">
      <a className="brand" href="#overview" aria-label="Placement demonstration home"><span className="brand-mark"><Icon name="shield" size={23} /></span><span className="brand-copy"><strong>Decentralized AI</strong><small>HONEYPOT NETWORK</small></span></a>
      <div className="nav-label">PUBLIC DEMONSTRATION</div>
      <nav className="nav-links">{[
        ["overview", "Overview", "chart"], ["sandbox", "Simulation Lab", "pulse"],
        ["sandbox-telemetry", "Telemetry", "pulse"], ["sandbox-detection", "Alerts & Incidents", "shield"],
        ["sandbox-profiles", "Behavior Analysis", "chart"], ["sandbox-deception", "Adaptive Deception", "layers"],
        ["sandbox-comparison", "Strategy Comparison", "runs"], ["sandbox-intelligence", "Intelligence Exchange", "runs"],
        ["verified-baseline", "Verified Lab Baseline", "chart"],
      ].map(([id, label, icon]) => <a className={`nav-link${activeNav === id ? " active" : ""}`} aria-current={activeNav === id ? "location" : undefined} key={id} href={`#${id}`} onClick={() => setActiveNav(id)}><Icon name={icon} /><span>{label}</span></a>)}</nav>
      <div className="sidebar-bottom"><div className="sidebar-status"><span className="mini-shield"><Icon name="shield" size={18} /></span><div><strong>Interactive sandbox</strong><small>Synthetic browser data</small></div></div></div>
    </aside>
    <main className="main-content" id="overview">
      <header className="topbar"><div className="crumb"><span>Placement Edition</span><b>/</b><strong>Public demo</strong></div><div className="top-actions"><span className="connection-pill connection-connected"><span className="status-dot" />{loading ? "Loading" : error ? "Unavailable" : "Demo data"}</span></div></header>
      <div className="page-wrap">
        <section className="page-title-row"><div><div className="eyebrow">INTERACTIVE SECURITY SANDBOX — SYNTHETIC DATA</div><h1>Explore the honeypot network</h1><p>Run bounded scenarios and inspect their generated events, rule signals, profiles, and strategy outcomes.</p></div><a className="primary-button" href="#sandbox">Start Simulation Lab <span aria-hidden="true">→</span></a></section>
        <InteractiveSandbox />
        {snapshot && <div className="alert alert-success" role="note"><strong>{snapshot.label}</strong><span>{snapshot.notice}</span></div>}
        {error && <div className="alert alert-error" role="alert"><strong>Demo service unavailable</strong><span>The backend may be starting after an idle period. {error}</span><button className="secondary-button" onClick={load} disabled={loading}>Retry</button></div>}
        {loading && !snapshot && <section className="panel public-demo-empty"><p role="status">Loading the demonstration snapshot. A free backend may need time to wake.</p></section>}
        {snapshot && <>
          <section className="verified-baseline" id="verified-baseline" aria-labelledby="verified-baseline-title"><div className="baseline-title"><div><span className="eyebrow">PREVIOUSLY VERIFIED CONTROLLED LOCAL LAB BASELINE</span><h2 id="verified-baseline-title">Cowrie placement walkthrough results</h2><p>This is a published historical snapshot, separate from the current browser sandbox run.</p></div></div><div className="kpi-grid" aria-label="Verified local baseline metrics">{publicDemoMetrics(snapshot).map((item) => <KpiCard key={item.label} label={item.label} value={item.value} detail={item.detail} icon="pulse" />)}</div></section>

          <section className="panel live-telemetry-panel" id="telemetry" aria-label="Previously verified local baseline telemetry and alerts">
            <div className="section-heading"><div><span className="eyebrow">SYNTHETIC SAMPLE</span><h2>Telemetry &amp; security alerts</h2><p>Curated, bounded examples. No live sensor ingestion is enabled here.</p></div><span className="incident-total">{snapshot.telemetry.length} event examples</span></div>
            <div className="live-feed-grid"><div className="live-feed-column"><h3>Recent telemetry</h3><ul className="live-event-list">{snapshot.telemetry.map((event, index) => <li key={`${event.event_type}-${index}`}><span className={`severity-dot severity-${event.severity}`} /><div><strong>{event.event_type}</strong><small>{event.source_system} · {new Date(event.timestamp).toLocaleString()}</small><small>{event.summary}</small></div><span className="live-severity">{event.severity}</span></li>)}</ul></div>
              <div className="live-feed-column alert-feed-column"><h3>Alert examples</h3><ul className="live-event-list">{snapshot.alerts.map((alert, index) => <li key={`${alert.rule}-${index}`}><span className={`severity-dot severity-${alert.severity}`} /><div><strong>{alert.rule}</strong><small>{alert.source_system} · {new Date(alert.timestamp).toLocaleString()}</small><small>{alert.summary}</small></div><span className="live-severity">{alert.severity}</span></li>)}</ul></div></div>
          </section>

          <section className="panel cowrie-panel" aria-label="Controlled local Cowrie SSH activity"><div className="section-heading"><div><span className="eyebrow">CONTROLLED LOCAL COWRIE RUN · AGGREGATE ONLY</span><h2>SSH honeypot activity</h2><p>Counts reproduce the verified local run using invented credentials. Sample summaries are sanitized; credentials, commands, and file contents are absent.</p></div></div>
            <div className="incident-counts"><span><strong>{snapshot.cowrie.failed_logins}</strong>failed logins</span><span><strong>{snapshot.cowrie.successful_logins}</strong>successful emulated logins</span><span><strong>{snapshot.cowrie.session_events}</strong>session events</span><span><strong>{snapshot.cowrie.command_attempts}</strong>command attempts</span></div>
            <ul className="incident-list">{snapshot.cowrie.events.map((event, index) => <li className="incident-item" key={`${event.event_type}-${index}`}><div className="incident-main"><span className="severity-dot severity-low" /><div><strong>{event.summary}</strong><small>{event.event_type} · {new Date(event.timestamp).toLocaleString()}</small></div></div></li>)}</ul>
          </section>

          <section className="panel incident-panel" id="incidents" aria-label="Synthetic incidents"><div className="section-heading"><div><span className="eyebrow">RULE-BASED CORRELATION</span><h2>Incidents</h2><p>Confidence represents rule evidence, not probability of compromise.</p></div><span className="incident-total">{snapshot.incidents.length} example</span></div>
            <ul className="incident-list">{snapshot.incidents.map((incident, index) => <li className="incident-item" key={`${incident.status}-${index}`}><div className="incident-main"><span className={`severity-dot severity-${incident.severity}`} /><div><strong>{incident.severity} · {incident.status}</strong><small>{Math.round(incident.confidence * 100)}% rule evidence · {new Date(incident.observed_at).toLocaleString()}</small></div></div><ul className="incident-evidence">{incident.evidence.map((evidence) => <li key={evidence}>{evidence}</li>)}</ul><div className="incident-tags">{incident.rules.map((rule) => <code key={rule}>{rule}</code>)}{incident.sensors.map((sensor) => <span key={sensor}>{sensor}</span>)}</div></li>)}</ul>
          </section>

          <section className="panel behavior-panel" aria-label="Controlled local behavior profile result"><div className="section-heading"><div><span className="eyebrow">PRECOMPUTED CONTROLLED LOCAL RESULT</span><h2>Attacker behavior profile</h2><p>This aggregate came from the verified invented-credential Cowrie lab run. The model was trained on synthetic data; the predicted category does not establish intent.</p></div></div>
            <div className="profile-list">{snapshot.profiles.map((profile, index) => <article className="profile-card" key={`${profile.classification}-${index}`}><div className="profile-card-body"><div className="recommendation-head"><div><span className="eyebrow">{profile.observations} observations</span><h3>{profile.classification.replaceAll("_", " ")}</h3></div><span className="recommendation-state">cluster {profile.cluster}</span></div><div className="incident-counts"><span><strong>{profile.anomaly_index.toFixed(3)}</strong>anomaly index</span><span><strong>{profile.model_version}</strong>model</span></div><p className="profile-note">{profile.provenance} {profile.basis}</p></div></article>)}</div>
          </section>

          <section className="panel behavior-panel" id="recommendations" aria-label="Synthetic deception recommendations"><div className="section-heading"><div><span className="eyebrow">EXPLICIT REVIEW WORKFLOW</span><h2>Adaptive deception recommendations</h2><p>Approval is a recorded state only. The public demo cannot evaluate or approve recommendations.</p></div></div>
            <div className="recommendation-list">{snapshot.recommendations.map((item, index) => <article className="recommendation-card" key={`${item.strategy}-${index}`}><div className="recommendation-head"><div><span className="eyebrow">{item.category.replaceAll("_", " ")}</span><h3>{item.title}</h3></div><span className={`recommendation-state state-${item.status}`}>{item.status}</span></div><p>{item.summary}</p><div className="recommendation-meta"><span>Strategy: <code>{item.strategy}</code></span></div>{item.evaluation && <div className="evaluation-evidence"><strong>Local synthetic evaluation: {item.evaluation.outcome}</strong><span>Interactions: {item.evaluation.interactions_recorded} / {item.evaluation.interactions_attempted}</span><span>Decoys generated: {item.evaluation.generated_decoys} · duration: {item.evaluation.elapsed_ms.toFixed(1)} ms</span><small>{item.evaluation.provenance} · {item.evaluation.observed_at}</small></div>}<small className="recommendation-warning">No decoy is deployed and no network control is changed.</small></article>)}</div>
          </section>

          <section className="panel network-operations-panel" id="intelligence" aria-label="Strategy intelligence exchange"><div className="section-heading"><div><span className="eyebrow">REPLICATION PROTOTYPE</span><h2>Decentralized intelligence</h2><p>{snapshot.intelligence.note}</p></div><span className="recommendation-state">{snapshot.intelligence.public_demo_peer_state.replaceAll("_", " ")}</span></div><p className="network-dashboard-note">Signed strategy and threat-intelligence exchange is demonstrated in isolated local nodes. This public service has no active peer links or consensus network.</p></section>
        </>}
        <footer className="page-footer"><span>Decentralized AI Honeypot Network</span><span>Public snapshot is read-only; sandbox actions stay in this browser</span><span>Snapshot refreshed {snapshot ? new Date(snapshot.updated_at).toLocaleString() : "when available"}</span></footer>
      </div>
    </main>
  </div>;
}

function AdminSessionGate() {
  const [state, setState] = useState("checking");
  const [token, setToken] = useState("");
  const [error, setError] = useState("");
  const [expiresIn, setExpiresIn] = useState(0);
  const [role, setRole] = useState("");

  useEffect(() => {
    let active = true;
    getAdminSession().then((session) => {
      if (active) { setExpiresIn(session.expires_in); setRole(session.role); setState("authenticated"); }
    }).catch(() => { if (active) setState("anonymous"); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (state !== "authenticated" || !expiresIn) return undefined;
    const timer = setTimeout(() => setState("anonymous"), expiresIn * 1000);
    return () => clearTimeout(timer);
  }, [state, expiresIn]);

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      const session = await loginAdmin(token);
      setToken("");
      setExpiresIn(session.expires_in);
      setRole(session.role);
      setState("authenticated");
    } catch (loginError) {
      setToken("");
      setError(loginError.message);
    }
  }

  async function signOut() {
    try { await logoutAdmin(); } finally { setState("anonymous"); setExpiresIn(0); }
  }

  if (state === "checking") return <main className="auth-screen"><p role="status">Checking administrator session…</p></main>;
  if (state === "authenticated") return <AuthenticatedApp role={role} onLogout={role === "admin" ? signOut : null} />;
  return <main className="auth-screen"><form className="auth-card" onSubmit={submit}>
    <span className="eyebrow">LOCAL ADMINISTRATOR SESSION</span><h1>Sign in to the dashboard</h1>
    <p>Enter the backend administrator token. It is exchanged for a short-lived, HttpOnly session and is not saved in browser storage.</p>
    <label className="field"><span>Administrator token</span><input type="password" value={token} onChange={(event) => setToken(event.target.value)} minLength={32} maxLength={512} autoComplete="off" required /></label>
    {error && <p className="auth-error" role="alert">{error}</p>}
    <button className="primary-button" type="submit">Sign in</button>
  </form></main>;
}

export default function App() {
  return import.meta.env.VITE_PUBLIC_DEMO === "true" ? <PublicDemoDashboard /> : <AdminSessionGate />;
}
