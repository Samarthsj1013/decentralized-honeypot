const configuredBase = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
export const API_BASE_URL = configuredBase.replace(/\/+$/, "");
let csrfToken = "";

export async function getAdminSession() {
  const result = await request("/auth/session");
  csrfToken = result.csrf_token;
  return result;
}

export function getPublicDemo() {
  return request("/public-demo");
}

export async function loginAdmin(adminToken) {
  const result = await request("/auth/session", {
    method: "POST",
    body: JSON.stringify({ admin_token: adminToken }),
    skipCsrf: true,
  });
  csrfToken = result.csrf_token;
  return result;
}

export async function logoutAdmin() {
  try { return await request("/auth/session", { method: "DELETE" }); }
  finally { csrfToken = ""; }
}

async function request(path, options = {}) {
  let response;
  const { skipCsrf = false, ...fetchOptions } = options;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...fetchOptions,
      credentials: "include",
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.method && !["GET", "HEAD", "OPTIONS"].includes(options.method.toUpperCase()) && !skipCsrf && csrfToken
          ? { "X-CSRF-Token": csrfToken } : {}),
        ...options.headers,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Network request failed";
    throw new Error(`Could not reach the API at ${API_BASE_URL}. ${message}`);
  }

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = payload?.detail;
    const message = Array.isArray(detail)
      ? detail.map((item) => item.msg || JSON.stringify(item)).join("; ")
      : detail || `${response.status} ${response.statusText}`;
    throw new Error(String(message));
  }
  return payload;
}

export async function getNetworkNodeDashboard() {
  return request("/network-node/dashboard");
}

export function getScenarios() {
  return request("/simulation/scenarios");
}

export function runEvaluation(body) {
  return request("/evaluations", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export function getEvaluation(evaluationId) {
  return request(`/evaluations/${encodeURIComponent(evaluationId)}`);
}

export function getTelemetryAlerts(limit = 30) {
  return request(`/telemetry/alerts?limit=${encodeURIComponent(limit)}`);
}

export function getCowrieEvents(limit = 30) {
  return request(`/telemetry/cowrie/events?limit=${encodeURIComponent(limit)}`);
}

export function getIncidents({ limit = 20, offset = 0, status } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (status) params.set("status", status);
  return request(`/incidents?${params.toString()}`);
}

export function getIncidentStats() {
  return request("/incidents/stats");
}

export function updateIncident(incidentId, action) {
  if (!["acknowledge", "resolve"].includes(action)) throw new Error("Unsupported incident action");
  return request(`/incidents/${encodeURIComponent(incidentId)}/${action}`, { method: "POST" });
}

export function getBehaviorProfiles({ limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  return request(`/profiles?${params.toString()}`);
}

export function getProfileStats() {
  return request("/profiles/stats");
}

export function recomputeProfiles(windowSeconds = 3600) {
  return request("/profiles/recompute", {
    method: "POST",
    body: JSON.stringify({ window_seconds: windowSeconds }),
  });
}

export function getDeceptionRecommendations({ limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  return request(`/deception/recommendations?${params.toString()}`);
}

export function evaluateDeceptionRecommendation(recommendationId) {
  return request(`/deception/recommendations/${encodeURIComponent(recommendationId)}/evaluate`, { method: "POST" });
}

export function approveDeceptionRecommendation(recommendationId) {
  return request(`/deception/recommendations/${encodeURIComponent(recommendationId)}/approve`, { method: "POST" });
}

export function runExperiment(body) {
  return request("/experiments/run", { method: "POST", body: JSON.stringify(body) });
}

export function getExperiments({ limit = 20, offset = 0 } = {}) {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  return request(`/experiments?${params.toString()}`);
}

export function getExperiment(experimentId) {
  return request(`/experiments/${encodeURIComponent(experimentId)}`);
}

export function experimentReportUrl(experimentId, format = "json") {
  if (!["json", "csv", "markdown"].includes(format)) throw new Error("Unsupported experiment report format");
  return `${API_BASE_URL}/experiments/${encodeURIComponent(experimentId)}/report?format=${format}`;
}

export async function downloadExperimentReport(experimentId, format = "json") {
  const response = await fetch(experimentReportUrl(experimentId, format), {
    credentials: "include",
    headers: { Accept: "application/octet-stream" },
  });
  if (!response.ok) throw new Error(`Report download failed (${response.status})`);
  const blobUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = `experiment-${experimentId}.${format === "markdown" ? "md" : format}`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

export function openTelemetryStream({ onEvent, onAlert, onCowrie, onIncident, onStatus }) {
  let stopped = false;
  let controller;
  const dispatch = (eventName, data) => {
    try {
      const value = JSON.parse(data);
      ({ event: onEvent, alert: onAlert, cowrie: onCowrie, incident: onIncident })[eventName]?.(value);
    } catch { /* Ignore malformed server frames. */ }
  };
  const connect = async () => {
    while (!stopped) {
      controller = new AbortController();
      try {
        const headers = { Accept: "text/event-stream" };
        const response = await fetch(`${API_BASE_URL}/telemetry/stream`, { headers, signal: controller.signal, credentials: "include" });
        if (!response.ok || !response.body) throw new Error(`Telemetry stream returned ${response.status}`);
        onStatus?.("connected");
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let eventName = "message";
        let data = [];
        while (!stopped) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split(/\r?\n/);
          buffer = lines.pop() || "";
          for (const line of lines) {
            if (!line) {
              if (data.length) dispatch(eventName, data.join("\n"));
              eventName = "message";
              data = [];
            } else if (line.startsWith("event:")) eventName = line.slice(6).trim();
            else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
          }
        }
      } catch {
        if (!stopped) onStatus?.("reconnecting");
      }
      if (!stopped) await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  };
  connect();
  return { close() { stopped = true; controller?.abort(); } };
}
