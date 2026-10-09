import { useEffect, useState } from "react";
import { api, formatSize, formatTime } from "../api.js";

const LABELS = {
  active_users: "Active users", active_sessions: "Active sessions", locked_accounts: "Locked accounts",
  disabled_accounts: "Disabled accounts", current_sessions: "Current sessions", device_count: "Devices",
  expired_sessions: "Expired sessions", uploads: "Uploads", downloads: "Downloads", rejected_files: "Rejected files",
  integrity_failures: "Integrity failures", packets_analyzed: "Packets analyzed", connections: "Connections",
  failed_connections: "Failed connections", suspicious_events: "Suspicious events", failed_logins: "Failed logins",
  unauthorized_requests: "Unauthorized requests", external_access_attempts: "External access attempts",
  rate_limited: "Rate-limited clients",
};
const WARN = ["locked_accounts", "integrity_failures", "rejected_files", "failed_connections", "suspicious_events",
  "failed_logins", "unauthorized_requests", "external_access_attempts", "rate_limited"];

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [captureId, setCaptureId] = useState("");
  const [error, setError] = useState("");

  const reload = () =>
    api(`/api/admin/dashboard${captureId ? `?capture_id=${captureId}` : ""}`).then(setData).catch((e) => setError(e.message));
  useEffect(() => {
    reload();
  }, [captureId]);

  if (error) return <div className="alert error">{error}</div>;
  if (!data) return <p className="muted">Loading…</p>;

  const group = (title, obj) => (
    <section className="card">
      <h2>{title}</h2>
      <div className="tiles">
        {Object.entries(obj)
          .filter(([k, v]) => typeof v === "number")
          .map(([k, v]) => (
            <div key={k} className={`tile ${WARN.includes(k) && v > 0 ? "warn" : ""}`}>
              <div className="tile-value">{v}</div>
              <div className="tile-label">{LABELS[k] || k}</div>
            </div>
          ))}
      </div>
    </section>
  );

  const cap = data.network.capture;
  return (
    <div className="stack">
      <div className="row-between">
        <h1 className="page-title">Security dashboard</h1>
        <button className="ghost" onClick={reload}>Refresh</button>
      </div>
      <div className="dash-grid">
        {group("Users", data.users)}
        {group("Sessions", data.sessions)}
        {group("Files", data.files)}
        {group("Security", data.security)}
      </div>

      <section className="card">
        <div className="row-between">
          <h2>Network {cap && <span className="muted small">capture “{cap.label}” ({cap.mode.toUpperCase()})</span>}</h2>
          {data.captures.length > 0 && (
            <select value={captureId || cap?.capture_id} onChange={(e) => setCaptureId(e.target.value)}>
              {data.captures.map((c) => (
                <option key={c.capture_id} value={c.capture_id}>#{c.capture_id} {c.label}</option>
              ))}
            </select>
          )}
        </div>
        {!cap ? (
          <p className="muted">No PCAP imported yet. Run <code>analysis/pcap_to_sqlite.py</code> on a Wireshark capture.</p>
        ) : (
          <div className="tiles">
            {["packets_analyzed", "connections", "failed_connections", "suspicious_events"].map((k) => (
              <div key={k} className={`tile ${WARN.includes(k) && data.network[k] > 0 ? "warn" : ""}`}>
                <div className="tile-value">{data.network[k]}</div>
                <div className="tile-label">{LABELS[k]}</div>
              </div>
            ))}
            <div className={`tile ${cap.plaintext_exposures > 0 ? "warn" : ""}`}>
              <div className="tile-value">{cap.plaintext_exposures}</div>
              <div className="tile-label">Plaintext exposures</div>
            </div>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Security alerts {cap && <span className="muted small">from capture #{cap.capture_id}</span>}</h2>
        {data.security.security_alerts.length === 0 && <p className="muted">No suspicious traffic patterns detected.</p>}
        {data.security.security_alerts.length > 0 && (
          <div className="table-wrap">
            <table className="dense">
              <thead><tr><th>Severity</th><th>Rule</th><th>Source IP</th><th>Count</th><th>Details</th></tr></thead>
              <tbody>
                {data.security.security_alerts.map((e) => (
                  <tr key={e.event_id}>
                    <td><span className={`badge ${e.severity === "high" ? "danger" : e.severity === "medium" ? "warn" : ""}`}>{e.severity}</span></td>
                    <td>{e.rule}</td>
                    <td className="mono">{e.source_ip}</td>
                    <td>{e.count}</td>
                    <td className="small">{e.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {data.captures.length > 0 && (
        <section className="card">
          <h2>Imported captures</h2>
          <div className="table-wrap">
            <table className="dense">
              <thead><tr><th>#</th><th>Label</th><th>Mode</th><th>Imported</th><th>Packets</th><th>Connections</th><th>Failed</th><th>Wire bytes</th><th>Payload bytes</th><th>Overhead</th><th>Plaintext exposures</th></tr></thead>
              <tbody>
                {data.captures.map((c) => (
                  <tr key={c.capture_id}>
                    <td>{c.capture_id}</td>
                    <td>{c.label}</td>
                    <td>{c.mode}</td>
                    <td className="nowrap">{formatTime(c.imported_at)}</td>
                    <td>{c.packet_count}</td>
                    <td>{c.connections}</td>
                    <td>{c.failed_connections}</td>
                    <td>{formatSize(c.wire_bytes)}</td>
                    <td>{formatSize(c.payload_bytes)}</td>
                    <td>{c.payload_bytes ? `${((c.wire_bytes / c.payload_bytes - 1) * 100).toFixed(1)}%` : "n/a"}</td>
                    <td>{c.plaintext_exposures}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
}
