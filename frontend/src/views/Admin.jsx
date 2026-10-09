import { useEffect, useState } from "react";
import { api, formatTime } from "../api.js";

export const ADMIN_PERMISSIONS = ["manage_users", "manage_roles", "manage_file_types", "manage_sessions", "view_audit"];

const EVENT_TYPES = [
  "LOGIN", "LOGIN_FAILED", "LOGOUT", "SESSION_CREATED", "SESSION_TERMINATED", "SESSION_EXPIRED",
  "FILE_UPLOAD", "FILE_DOWNLOAD", "FILE_SHARE", "ACCESS_DENIED", "INTEGRITY_FAILURE", "INTEGRITY_VERIFIED",
  "INVALID_FILE_TYPE", "EXTERNAL_ACCESS_ATTEMPT", "RATE_LIMITED", "ADMIN_ACTION",
];

export default function Admin({ me }) {
  const can = (p) => me.permissions.includes(p);
  const sections = [
    ["users", "Users", can("manage_users")],
    ["roles", "Roles", can("manage_users")],
    ["types", "File types", can("manage_file_types")],
    ["sessions", "Sessions", can("manage_sessions")],
    ["audit", "Audit log", can("view_audit")],
  ].filter((s) => s[2]);
  const [section, setSection] = useState(sections[0]?.[0]);

  return (
    <div className="stack">
      <nav className="subtabs">
        {sections.map(([id, label]) => (
          <button key={id} className={id === section ? "tab active" : "tab"} onClick={() => setSection(id)}>
            {label}
          </button>
        ))}
      </nav>
      {section === "users" && <Users me={me} />}
      {section === "roles" && <Roles canEdit={can("manage_roles")} />}
      {section === "types" && <FileTypes />}
      {section === "sessions" && <AllSessions />}
      {section === "audit" && <Audit />}
    </div>
  );
}

function useAction(reload) {
  const [msg, setMsg] = useState(null);
  const run = async (fn, okText) => {
    try {
      await fn();
      setMsg({ kind: "ok", text: okText });
      reload?.();
    } catch (e) {
      setMsg({ kind: "error", text: e.message });
    }
  };
  return [msg, run];
}

function Users({ me }) {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const blank = { user_id: "", name: "", department: "", role: "", password: "" };
  const [form, setForm] = useState(blank);
  const reload = () => api("/api/admin/users").then(setUsers);
  const [msg, run] = useAction(reload);

  useEffect(() => {
    reload();
    api("/api/admin/roles").then((r) => setRoles(r.roles.map((x) => x.name)));
  }, []);

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });
  const create = (e) => {
    e.preventDefault();
    run(async () => {
      await api("/api/admin/users", { method: "POST", body: form });
      setForm(blank);
    }, `User ${form.user_id} created`);
  };
  const patch = (id, body, text) => run(() => api(`/api/admin/users/${id}`, { method: "PATCH", body }), text);

  return (
    <>
      <form className="card form-grid" onSubmit={create}>
        <h2 className="full">Create company user</h2>
        <label>
          User ID (login name)
          <input
            value={form.user_id}
            onChange={set("user_id")}
            required
            minLength={3}
            maxLength={64}
            pattern="[A-Za-z0-9_.\-]+"
            title="3 to 64 characters: letters, numbers, dot (.), dash (-) or underscore (_). No spaces. Example: fin_carl"
            placeholder="e.g. fin_carl"
          />
        </label>
        <label>Name<input value={form.name} onChange={set("name")} required /></label>
        <label>Department<input value={form.department} onChange={set("department")} required /></label>
        <label>
          Role
          <select value={form.role} onChange={set("role")} required>
            <option value="">Choose…</option>
            {roles.map((r) => <option key={r}>{r}</option>)}
          </select>
        </label>
        <label>Initial password<input type="password" value={form.password} onChange={set("password")} required minLength={8} autoComplete="new-password" /></label>
        <div className="full"><button className="primary">Create user</button></div>
      </form>
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
      <section className="card">
        <h2>Users</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>User ID</th><th>Name</th><th>Department</th><th>Role</th><th>Status</th><th>Sessions</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.user_id}>
                  <td className="mono">{u.user_id}</td>
                  <td>{u.name}</td>
                  <td>{u.department}</td>
                  <td>
                    <select value={u.role} disabled={u.user_id === me.user_id}
                      onChange={(e) => patch(u.user_id, { role: e.target.value }, `Role of ${u.user_id} changed`)}>
                      {roles.map((r) => <option key={r}>{r}</option>)}
                    </select>
                  </td>
                  <td><span className={`badge ${u.status === "active" ? "ok" : "danger"}`}>{u.status}</span></td>
                  <td>{u.active_sessions}</td>
                  <td className="actions">
                    {u.status !== "active" && (
                      <button onClick={() => patch(u.user_id, { status: "active" }, `${u.user_id} enabled`)}>
                        {u.status === "locked" ? "Unlock" : "Enable"}
                      </button>
                    )}
                    {u.status === "active" && u.user_id !== me.user_id && (
                      <button className="danger" onClick={() => patch(u.user_id, { status: "disabled" }, `${u.user_id} disabled`)}>Disable</button>
                    )}
                    <button onClick={() => {
                      const pw = window.prompt(`New password for ${u.user_id} (min 8 characters)`);
                      if (pw) patch(u.user_id, { password: pw }, `Password reset for ${u.user_id}`);
                    }}>Reset password</button>
                    {u.active_sessions > 0 && (
                      <button onClick={() => run(() => api(`/api/admin/users/${u.user_id}/sessions`, { method: "DELETE" }), `All sessions of ${u.user_id} revoked`)}>
                        Revoke sessions
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function Roles({ canEdit }) {
  const [data, setData] = useState({ all_permissions: [], roles: [] });
  const [newRole, setNewRole] = useState("");
  const reload = () => api("/api/admin/roles").then(setData);
  const [msg, run] = useAction(reload);
  useEffect(() => {
    reload();
  }, []);

  const toggle = (role, perm) =>
    setData({
      ...data,
      roles: data.roles.map((r) =>
        r.role_id !== role.role_id ? r
          : { ...r, permissions: r.permissions.includes(perm) ? r.permissions.filter((p) => p !== perm) : [...r.permissions, perm] }
      ),
    });

  return (
    <section className="card">
      <h2>Roles &amp; permissions</h2>
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
      <div className="table-wrap">
        <table>
          <thead>
            <tr><th>Role</th>{data.all_permissions.map((p) => <th key={p} className="small">{p.replaceAll("_", " ")}</th>)}<th /></tr>
          </thead>
          <tbody>
            {data.roles.map((r) => (
              <tr key={r.role_id}>
                <td><strong>{r.name}</strong></td>
                {data.all_permissions.map((p) => (
                  <td key={p} className="center-cell">
                    <input type="checkbox" checked={r.permissions.includes(p)} disabled={!canEdit || !r.editable} onChange={() => toggle(r, p)} />
                  </td>
                ))}
                <td>
                  {canEdit && r.editable && (
                    <button onClick={() => run(() => api(`/api/admin/roles/${r.role_id}`, { method: "PUT", body: { name: r.name, permissions: r.permissions } }), `${r.name} saved`)}>
                      Save
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {canEdit && (
        <form className="inline-form" onSubmit={(e) => {
          e.preventDefault();
          run(async () => {
            await api("/api/admin/roles", { method: "POST", body: { name: newRole, permissions: ["send_message", "download_file"] } });
            setNewRole("");
          }, `Role ${newRole} created`);
        }}>
          <input placeholder="New role name (e.g. Legal)" value={newRole} onChange={(e) => setNewRole(e.target.value)} required minLength={2} />
          <button className="primary">Add role</button>
        </form>
      )}
    </section>
  );
}

function FileTypes() {
  const [types, setTypes] = useState([]);
  const reload = () => api("/api/admin/file-types").then(setTypes);
  const [msg, run] = useAction(reload);
  useEffect(() => {
    reload();
  }, []);
  const patch = (ext, body) => run(() => api(`/api/admin/file-types/${ext}`, { method: "PATCH", body }), `.${ext} updated`);

  return (
    <section className="card">
      <h2>Allowed file types</h2>
      <p className="muted small">Only types with a known file signature can be allowed. Disabled types are rejected on upload.</p>
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>Extension</th><th>MIME type</th><th>Category</th><th>Allowed</th><th>Browser compatible</th></tr></thead>
          <tbody>
            {types.map((t) => (
              <tr key={t.ext}>
                <td className="mono">.{t.ext}</td>
                <td className="small mono">{t.mime}</td>
                <td>{t.category}</td>
                <td className="center-cell"><input type="checkbox" checked={!!t.enabled} onChange={(e) => patch(t.ext, { enabled: e.target.checked })} /></td>
                <td className="center-cell"><input type="checkbox" checked={!!t.browser_compatible} onChange={(e) => patch(t.ext, { browser_compatible: e.target.checked })} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function AllSessions() {
  const [rows, setRows] = useState([]);
  const reload = () => api("/api/admin/sessions").then(setRows);
  const [msg, run] = useAction(reload);
  useEffect(() => {
    reload();
  }, []);

  return (
    <section className="card">
      <div className="row-between">
        <h2>Active sessions</h2>
        <button className="ghost" onClick={reload}>Refresh</button>
      </div>
      {msg && <div className={`alert ${msg.kind}`}>{msg.text}</div>}
      <div className="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Device</th><th>Signed in</th><th>Last activity</th><th>Expires</th><th /></tr></thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.session_id}>
                <td className="mono">{s.user_id}</td>
                <td>{s.device_label}<div className="muted small mono">{s.device_id.slice(0, 8)}</div></td>
                <td>{formatTime(s.created_at)}</td>
                <td>{formatTime(s.last_activity)}</td>
                <td>{formatTime(s.expires_at)}</td>
                <td className="actions">
                  <button className="danger" onClick={() => run(() => api(`/api/admin/sessions/${s.session_id}`, { method: "DELETE" }), "Session revoked")}>Revoke</button>
                  <button onClick={() => run(() => api(`/api/admin/users/${s.user_id}/sessions`, { method: "DELETE" }), `All sessions of ${s.user_id} revoked`)}>Revoke all for user</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Audit() {
  const [rows, setRows] = useState([]);
  const [filters, setFilters] = useState({ user_id: "", event_type: "", since: "" });
  const [error, setError] = useState("");

  const reload = () => {
    const q = new URLSearchParams({ limit: "300" });
    if (filters.user_id) q.set("user_id", filters.user_id);
    if (filters.event_type) q.set("event_type", filters.event_type);
    if (filters.since) q.set("since", new Date(filters.since).toISOString().slice(0, 19) + "Z");
    api(`/api/admin/audit?${q}`).then(setRows).catch((e) => setError(e.message));
  };
  useEffect(() => {
    reload();
  }, []);
  const set = (k) => (e) => setFilters({ ...filters, [k]: e.target.value });

  return (
    <section className="card">
      <h2>Audit log</h2>
      <form className="inline-form" onSubmit={(e) => { e.preventDefault(); reload(); }}>
        <input placeholder="User ID" value={filters.user_id} onChange={set("user_id")} />
        <select value={filters.event_type} onChange={set("event_type")}>
          <option value="">All events</option>
          {EVENT_TYPES.map((t) => <option key={t}>{t}</option>)}
        </select>
        <input type="datetime-local" value={filters.since} onChange={set("since")} />
        <button className="primary">Filter</button>
      </form>
      {error && <div className="alert error">{error}</div>}
      <div className="table-wrap">
        <table className="dense">
          <thead><tr><th>Time</th><th>User</th><th>Device</th><th>Event</th><th>Resource</th><th>Request</th><th>Source IP</th><th>Result</th><th>Details</th></tr></thead>
          <tbody>
            {rows.map((a) => (
              <tr key={a.event_id}>
                <td className="nowrap">{formatTime(a.timestamp)}</td>
                <td className="mono">{a.user_id}</td>
                <td className="mono small">{a.device_id?.slice(0, 8)}</td>
                <td><span className={`badge ${/FAIL|DENIED|EXTERNAL|INVALID|RATE/.test(a.event_type) ? "danger" : ""}`}>{a.event_type}</span></td>
                <td className="small">{a.resource}</td>
                <td>{a.request_type}</td>
                <td className="mono small">{a.source_ip}</td>
                <td>{a.result}</td>
                <td className="small">{a.details}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
