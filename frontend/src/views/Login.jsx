import { useState } from "react";
import { api, broadcastAuthChange, deviceId } from "../api.js";

export default function Login({ notice, onLoggedIn }) {
  const [userId, setUserId] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api("/api/auth/login", {
        method: "POST",
        quiet401: true,
        body: { user_id: userId.trim(), password, device_id: deviceId() },
      });
      setPassword("");
      broadcastAuthChange();
      await onLoggedIn();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="card login" onSubmit={submit}>
        <h1>
          <span aria-hidden>🔒</span> SecureLink
        </h1>
        <p className="muted">Company intranet: authorized employees only.</p>
        {notice && <div className="alert info">{notice}</div>}
        {error && <div className="alert error">{error}</div>}
        <label>
          User ID
          <input value={userId} onChange={(e) => setUserId(e.target.value)} autoComplete="username" required />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        <button className="primary" disabled={busy}>
          {busy ? "Signing in…" : "Log in"}
        </button>
        <p className="muted small">Accounts are created by your administrator. There is no public sign-up.</p>
      </form>
    </div>
  );
}
