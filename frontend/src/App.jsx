import { useEffect, useState } from "react";
import { api, AUTH_EVENT_KEY, broadcastAuthChange, setSessionExpiredHandler } from "./api.js";
import Login from "./views/Login.jsx";
import Messages from "./views/Messages.jsx";
import Files from "./views/Files.jsx";
import Sessions from "./views/Sessions.jsx";
import Admin, { ADMIN_PERMISSIONS } from "./views/Admin.jsx";
import Dashboard from "./views/Dashboard.jsx";

export default function App() {
  const [me, setMe] = useState(null);
  const [checking, setChecking] = useState(true);
  const [notice, setNotice] = useState("");
  const [view, setView] = useState("messages");

  const loadMe = () =>
    api("/api/auth/me", { quiet401: true })
      .then((u) => {
        setMe(u);
        setNotice("");
      })
      .catch(() => setMe(null));

  useEffect(() => {
    setSessionExpiredHandler(() => {
      setMe(null);
      setNotice("Session expired. Please log in again");
    });
    loadMe().finally(() => setChecking(false));

    // Another tab logged in or out: this tab's cookie now belongs to someone else (or no one).
    const onStorage = (e) => {
      if (e.key !== AUTH_EVENT_KEY) return;
      api("/api/auth/me", { quiet401: true })
        .then((u) => {
          setMe(u);
          setNotice("");
        })
        .catch(() => {
          setMe(null);
          setNotice("You were logged out in another tab.");
        });
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  if (checking) return <div className="center muted">Loading…</div>;
  if (!me) return <Login notice={notice} onLoggedIn={loadMe} />;

  const can = (p) => me.permissions.includes(p);
  const tabs = [
    ["messages", "Messages", can("send_message")],
    ["files", "Files", can("download_file") || can("upload_file")],
    ["sessions", "Sessions", true],
    ["admin", "Admin", ADMIN_PERMISSIONS.some(can)],
    ["dashboard", "Dashboard", can("view_dashboard")],
  ].filter((t) => t[2]);
  const current = tabs.some((t) => t[0] === view) ? view : tabs[0][0];

  const logout = async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } finally {
      broadcastAuthChange();
      setMe(null);
      setNotice("You have been logged out.");
    }
  };

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo" aria-hidden>🔒</span> SecureLink
        </div>
        <nav className="tabs">
          {tabs.map(([id, label]) => (
            <button key={id} className={id === current ? "tab active" : "tab"} onClick={() => setView(id)}>
              {label}
            </button>
          ))}
        </nav>
        <div className="who">
          <span className="who-name">
            {me.name} <span className="badge">{me.role}</span>
          </span>
          <button className="ghost" onClick={logout}>
            Log out
          </button>
        </div>
      </header>
      {/* keyed by user so no state from a previous account survives an account switch */}
      <main className="content" key={me.user_id}>
        {current === "messages" && <Messages me={me} />}
        {current === "files" && <Files me={me} />}
        {current === "sessions" && <Sessions onLogout={logout} />}
        {current === "admin" && <Admin me={me} />}
        {current === "dashboard" && <Dashboard />}
      </main>
    </div>
  );
}
