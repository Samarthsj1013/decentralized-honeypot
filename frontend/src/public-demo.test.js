import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import React from "react";
import { renderToString } from "react-dom/server";
import { createServer } from "vite";
import { PUBLIC_DEMO_LABEL, publicDemoMetrics } from "./public-demo.js";

test("public placement metrics use only the sanitized overview and label the data", () => {
  const metrics = publicDemoMetrics({
    label: PUBLIC_DEMO_LABEL,
    overview: { telemetry_events: 15, alerts: 2, incidents: 1, profiles: 1, recommendations: 2 },
  });
  assert.equal(PUBLIC_DEMO_LABEL, "Placement Demonstration — Synthetic Security Data");
  assert.deepEqual(metrics.map(({ value }) => value), ["15", "2", "1", "1", "2"]);
  assert.ok(metrics.every(({ detail }) => /synthetic|demo|example/i.test(detail)));
});

test("public placement metrics fail safely for missing or invalid counters", () => {
  const metrics = publicDemoMetrics({ overview: { telemetry_events: -1, alerts: "2" } });
  assert.equal(metrics[0].value, "Unavailable");
  assert.equal(metrics[1].value, "Unavailable");
  assert.equal(metrics[2].value, "Unavailable");
});

test("public demo renders a read-only view without mounting the admin session gate", () => {
  const source = readFileSync(new URL("./App.jsx", import.meta.url), "utf8");
  const publicView = source.slice(source.indexOf("function PublicDemoDashboard("), source.indexOf("function AdminSessionGate()"));
  assert.match(source, /VITE_PUBLIC_DEMO === "true" \? <PublicDemoDashboard \/> : <AdminSessionGate \/>/);
  assert.match(publicView, /getPublicDemo\(\)/);
  assert.match(publicView, /PUBLIC_DEMO_LABEL/);
  assert.match(publicView, /snapshot\.telemetry/);
  assert.match(publicView, /snapshot\.incidents/);
  assert.match(publicView, /snapshot\.profiles/);
  assert.match(publicView, /snapshot\.recommendations/);
  assert.doesNotMatch(publicView, /updateIncident\(|recomputeProfiles\(|approveDeceptionRecommendation\(|evaluateDeceptionRecommendation\(|runEvaluation\(|runExperiment\(/);
});

test("React renders populated public demo sections from the sanitized fixture", async () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const fixture = JSON.parse(readFileSync(new URL("../../backend/app/public_demo_data.json", import.meta.url), "utf8"));
  const vite = await createServer({
    configFile: fileURLToPath(new URL("../vite.config.js", import.meta.url)),
    root,
    appType: "custom",
    server: { middlewareMode: true },
  });
  try {
    const { PublicDemoDashboard } = await vite.ssrLoadModule("/src/App.jsx");
    const html = renderToString(React.createElement(PublicDemoDashboard, { initialSnapshot: fixture }));
    assert.match(html, /Placement Demonstration/);
    assert.match(html, /Telemetry &amp; security alerts/);
    assert.match(html, /SSH honeypot activity/);
    assert.match(html, /Incidents/);
    assert.match(html, /Attacker behavior profile/);
    assert.match(html, /Adaptive deception recommendations/);
    assert.match(html, /authentication probing/);
    assert.match(html, /approved/);
    assert.match(html, /pending/);
    assert.doesNotMatch(html, /Administrator token|Sign in to the dashboard|Acknowledge|Approve recommendation|Recompute profiles|Launch evaluation/);
    assert.doesNotMatch(html, /<button\b/);
  } finally {
    await vite.close();
  }
});
