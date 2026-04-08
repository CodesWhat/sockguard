"use client";

import { useState } from "react";
import { compileRules, evaluateCompiled, type EvalResult, type Rule } from "../lib/evaluate";

const DEFAULT_RULES: Rule[] = [
  { method: "GET", path: "/_ping", action: "allow" },
  { method: "GET", path: "/version", action: "allow" },
  { method: "GET", path: "/events", action: "allow" },
  { method: "GET", path: "/containers/**", action: "allow" },
  { method: "POST", path: "/containers/*/start", action: "allow" },
  { method: "POST", path: "/containers/*/stop", action: "allow" },
  { method: "*", path: "/**", action: "deny", reason: "no matching allow rule" },
];
const DEFAULT_COMPILED_RULES = compileRules(DEFAULT_RULES);

const SAMPLE_REQUESTS = [
  { method: "GET", path: "/v1.45/containers/json", label: "List containers" },
  { method: "GET", path: "/_ping", label: "Ping" },
  { method: "POST", path: "/v1.45/containers/abc123/start", label: "Start container" },
  { method: "POST", path: "/v1.45/containers/abc123/stop", label: "Stop container" },
  { method: "POST", path: "/v1.45/containers/create", label: "Create container" },
  { method: "POST", path: "/v1.45/containers/abc123/exec", label: "Exec into container" },
  { method: "DELETE", path: "/v1.45/containers/abc123", label: "Delete container" },
  { method: "GET", path: "/v1.45/images/json", label: "List images" },
  { method: "POST", path: "/v1.45/images/create", label: "Pull image" },
  { method: "GET", path: "/v1.45/networks/json", label: "List networks" },
];

export default function RuleTester() {
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/containers/json");
  const [result, setResult] = useState<EvalResult | null>(null);

  function handleTest() {
    setResult(evaluateCompiled(DEFAULT_COMPILED_RULES, method, path));
  }

  function handleSample(sampleMethod: string, samplePath: string) {
    setMethod(sampleMethod);
    setPath(samplePath);
    setResult(evaluateCompiled(DEFAULT_COMPILED_RULES, sampleMethod, samplePath));
  }

  return (
    <main style={{ maxWidth: 900, margin: "0 auto", padding: "2rem", fontFamily: "system-ui" }}>
      <h1>Sockguard Rule Tester</h1>
      <p>Test how sockguard rules evaluate Docker API requests.</p>

      <section>
        <h2>Rules</h2>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>
                #
              </th>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>
                Method
              </th>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>
                Path
              </th>
              <th style={{ textAlign: "left", padding: "0.5rem", borderBottom: "2px solid #333" }}>
                Action
              </th>
            </tr>
          </thead>
          <tbody>
            {DEFAULT_RULES.map((rule, i) => (
              <tr
                key={i}
                style={{
                  backgroundColor: result?.ruleIndex === i ? (result.action === "allow" ? "#d4edda" : "#f8d7da") : "transparent",
                }}
              >
                <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd" }}>{i}</td>
                <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd", fontFamily: "monospace" }}>
                  {rule.method}
                </td>
                <td style={{ padding: "0.5rem", borderBottom: "1px solid #ddd", fontFamily: "monospace" }}>
                  {rule.path}
                </td>
                <td
                  style={{
                    padding: "0.5rem",
                    borderBottom: "1px solid #ddd",
                    fontWeight: "bold",
                    color: rule.action === "allow" ? "#155724" : "#721c24",
                  }}
                >
                  {rule.action.toUpperCase()}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section style={{ marginTop: "2rem" }}>
        <h2>Test a Request</h2>
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            style={{ padding: "0.5rem", fontSize: "1rem" }}
          >
            <option>GET</option>
            <option>POST</option>
            <option>PUT</option>
            <option>DELETE</option>
            <option>HEAD</option>
          </select>
          <input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            style={{ padding: "0.5rem", fontSize: "1rem", flex: 1, fontFamily: "monospace" }}
            placeholder="/containers/json"
          />
          <button
            onClick={handleTest}
            style={{
              padding: "0.5rem 1rem",
              fontSize: "1rem",
              cursor: "pointer",
              backgroundColor: "#333",
              color: "#fff",
              border: "none",
              borderRadius: "4px",
            }}
          >
            Evaluate
          </button>
        </div>

        {result && (
          <div
            style={{
              marginTop: "1rem",
              padding: "1rem",
              borderRadius: "4px",
              backgroundColor: result.action === "allow" ? "#d4edda" : "#f8d7da",
              color: result.action === "allow" ? "#155724" : "#721c24",
              fontFamily: "monospace",
            }}
          >
            <strong>{result.action.toUpperCase()}</strong>
            {result.ruleIndex >= 0 ? ` (rule ${result.ruleIndex})` : ""} — {result.reason}
          </div>
        )}
      </section>

      <section style={{ marginTop: "2rem" }}>
        <h2>Sample Requests</h2>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
          {SAMPLE_REQUESTS.map((sample, i) => (
            <button
              key={i}
              onClick={() => handleSample(sample.method, sample.path)}
              style={{
                padding: "0.5rem 0.75rem",
                fontSize: "0.85rem",
                cursor: "pointer",
                border: "1px solid #ccc",
                borderRadius: "4px",
                backgroundColor: "#f8f9fa",
              }}
            >
              <span style={{ fontWeight: "bold" }}>{sample.method}</span> {sample.label}
            </button>
          ))}
        </div>
      </section>
    </main>
  );
}
