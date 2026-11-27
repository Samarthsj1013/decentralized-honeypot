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

test("public demo mounts the sandbox and avoids operator API mutations", () => {
  const source = readFileSync(new URL("./App.jsx", import.meta.url), "utf8");
  const publicView = source.slice(source.indexOf("function PublicDemoDashboard("), source.indexOf("function AdminSessionGate()"));
  assert.match(source, /VITE_PUBLIC_DEMO === "true" \? <PublicDemoDashboard \/> : <AdminSessionGate \/>/);
  assert.match(publicView, /getPublicDemo\(\)/);
  assert.match(publicView, /<InteractiveSandbox \/>/);
  assert.match(publicView, /Public snapshot is read-only; sandbox actions stay in this browser/);
  assert.match(publicView, /Start Simulation Lab/);
  assert.match(publicView, /snapshot\.telemetry/);
  assert.match(publicView, /snapshot\.incidents/);
  assert.match(publicView, /snapshot\.profiles/);
  assert.match(publicView, /snapshot\.recommendations/);
  assert.doesNotMatch(publicView, /updateIncident\(|recomputeProfiles\(|approveDeceptionRecommendation\(|evaluateDeceptionRecommendation\(|runEvaluation\(|runExperiment\(/);
  const sandbox = readFileSync(new URL("./InteractiveSandbox.jsx", import.meta.url), "utf8");
  assert.match(sandbox, /runSandboxSimulationAsync\(/);
  assert.match(sandbox, /No configured sandbox rule matched this run\. That does not establish the activity as benign\./);
  assert.doesNotMatch(sandbox, /useful benign\/control outcome/);
  assert.match(sandbox, /Approve in sandbox/);
  assert.doesNotMatch(sandbox, /localStorage|sessionStorage|fetch\(|https?:\/\//);
  assert.doesNotMatch(sandbox, /approveDeceptionRecommendation|runEvaluation|runExperiment|updateIncident\(/);
});

test("public snapshot fetch omits credentials while operator requests retain session cookies", () => {
  const source = readFileSync(new URL("./api.js", import.meta.url), "utf8");
  assert.match(source, /getPublicDemo\(\)\s*\{\s*return request\("\/public-demo", \{ credentials: "omit" \}\);/);
  assert.match(source, /credentials = "include"/);
  assert.match(source, /getAdminSession\(\)\s*\{\s*const result = await request\("\/auth\/session"\)/);
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
    assert.match(html, /INTERACTIVE SECURITY SANDBOX/i);
    assert.match(html, /Run Simulation/);
    assert.match(html, /Reset Sandbox/);
    assert.match(html, /Strategy Comparison/);
    assert.match(html, /Intelligence Exchange/);
    assert.match(html, /Verified Lab Baseline/);
    assert.match(html, /PREVIOUSLY VERIFIED CONTROLLED LOCAL LAB BASELINE/);
    assert.doesNotMatch(html, /Administrator token|Sign in to the dashboard|Acknowledge|Approve recommendation|Recompute profiles|Launch evaluation/);
    assert.match(html, /<button\b/);
  } finally {
    await vite.close();
  }
});
