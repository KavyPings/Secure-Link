import { useEffect, useState } from "react";
import { api, formatTime } from "../api.js";

export default function Sessions({ onLogout }) {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");

  const reload = () => api("/api/sessions").then(setRows).catch((e) => setError(e.message));
  useEffect(() => {
    reload();
  }, []);

  const revoke = async (s) => {
    if (s.current) return onLogout();
    try {
      await api(`/api/sessions/${s.session_id}`, { method: "DELETE" });
      reload();
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <section className="card">
      <h2>Your active devices</h2>
      <p className="muted small">
        You can be signed in on at most two devices. Sessions end after 8 hours, or after a period of inactivity.
      </p>
      {error && <div className="alert error">{error}</div>}
      {rows.map((s) => (
        <div key={s.session_id} className="file-row">
          <div className="file-main">
            <strong>{s.device_label}</strong> {s.current && <span className="badge ok">this device</span>}
            <div className="muted small">
              Signed in {formatTime(s.created_at)} · last active {formatTime(s.last_activity)} · expires{" "}
              {formatTime(s.expires_at)}
            </div>
          </div>
          <div className="file-actions">
            <button className={s.current ? "ghost" : "danger"} onClick={() => revoke(s)}>
              {s.current ? "Log out" : "Revoke"}
            </button>
          </div>
        </div>
      ))}
    </section>
  );
}
