const configuredBase = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000/api/v1";
export const API_BASE_URL = configuredBase.replace(/\/+$/, "");

async function request(path, options = {}) {
  let response;
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        Accept: "application/json",
        ...(options.body ? { "Content-Type": "application/json" } : {}),
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
