import { useEffect, useRef, useState } from "react";
import { api, formatSize, formatTime, sha256Hex } from "../api.js";

const ACCEPT = ".pdf,.docx,.xlsx,.pptx,.txt,.jpg,.jpeg,.png,.webp";
const IMAGE_TYPES = ["image/jpeg", "image/png", "image/webp"];

export default function Files({ me }) {
  const [files, setFiles] = useState({ received: [], sent: [] });
  const [error, setError] = useState("");
  const canUpload = me.permissions.includes("upload_file") && me.permissions.includes("share_file");
  const canDownload = me.permissions.includes("download_file");

  const reload = () =>
    canDownload &&
    api("/api/files")
      .then(setFiles)
      .catch((e) => setError(e.message));

  useEffect(() => {
    reload();
  }, []);

  return (
    <div className="stack">
      {canUpload && <UploadCard onUploaded={reload} />}
      {error && <div className="alert error">{error}</div>}
      {canDownload && (
        <>
          <section className="card">
            <div className="row-between">
              <h2>Received files</h2>
              <button className="ghost" onClick={reload}>
                Refresh
              </button>
            </div>
            {files.received.length === 0 && <p className="muted">Nothing has been shared with you yet.</p>}
            {files.received.map((f) => (
              <FileRow key={f.file_id} file={f} subtitle={`From ${f.sender_id} · ${formatTime(f.shared_at)}`} />
            ))}
          </section>
          <section className="card">
            <h2>Files you shared</h2>
            {files.sent.length === 0 && <p className="muted">You have not shared any files.</p>}
            {files.sent.map((f) => (
              <FileRow key={f.file_id} file={f} subtitle={`To ${f.recipients} · ${formatTime(f.created_at)}`} />
            ))}
          </section>
        </>
      )}
    </div>
  );
}

function UploadCard({ onUploaded }) {
  const [users, setUsers] = useState([]);
  const [recipients, setRecipients] = useState([]);
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState(null); // {kind: info|ok|error, text}
  const [busy, setBusy] = useState(false);
  const inputRef = useRef(null);

  useEffect(() => {
    api("/api/users").then(setUsers).catch(() => {});
  }, []);

  const toggle = (id) => setRecipients((r) => (r.includes(id) ? r.filter((x) => x !== id) : [...r, id]));

  const upload = async (e) => {
    e.preventDefault();
    if (!file || recipients.length === 0) {
      setStatus({ kind: "error", text: "Choose a file and at least one recipient." });
      return;
    }
    setBusy(true);
    try {
      setStatus({ kind: "info", text: "Computing SHA-256…" });
      const hash = await sha256Hex(await file.arrayBuffer());
      const form = new FormData();
      form.append("file", file);
      form.append("client_sha256", hash ?? "unavailable");
      recipients.forEach((r) => form.append("recipients", r));
      setStatus({ kind: "info", text: "Uploading over TLS…" });
      const res = await api("/api/files", { method: "POST", body: form });
      setStatus({ kind: "ok", text: `Shared with ${res.recipients.join(", ")}. SHA-256 ${res.sha256.slice(0, 16)}…` });
      setFile(null);
      setRecipients([]);
      if (inputRef.current) inputRef.current.value = "";
      onUploaded();
    } catch (err) {
      setStatus({ kind: "error", text: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card" onSubmit={upload}>
      <h2>Share a document or image</h2>
      <p className="muted small">Allowed: PDF, DOCX, XLSX, PPTX, TXT, JPG, PNG, WEBP. Files are checked by extension, MIME type and signature.</p>
      <input ref={inputRef} type="file" accept={ACCEPT} onChange={(e) => setFile(e.target.files[0] || null)} />
      {file && (
        <p className="small muted">
          {file.name} · {formatSize(file.size)}
        </p>
      )}
      <fieldset className="recipients">
        <legend>Recipients</legend>
        {users.map((u) => (
          <label key={u.user_id} className="check">
            <input type="checkbox" checked={recipients.includes(u.user_id)} onChange={() => toggle(u.user_id)} />
            {u.name} <span className="muted small">({u.department})</span>
          </label>
        ))}
      </fieldset>
      {status && <div className={`alert ${status.kind}`}>{status.text}</div>}
      <button className="primary" disabled={busy}>
        {busy ? "Working…" : "Upload & share"}
      </button>
    </form>
  );
}

// The file's API address. Opening it still requires login + owner/recipient access (403 otherwise).
function FileAddress({ fileId }) {
  const [copied, setCopied] = useState(false);
  const address = `${window.location.origin}/api/files/${fileId}`;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(address); // only available over HTTPS / localhost
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      window.prompt("Copy this address:", address);
    }
  };
  return (
    <div className="muted small mono file-address">
      <span>{address}</span>
      <button type="button" className="ghost link-button" onClick={copy}>
        {copied ? "Copied ✓" : "Copy"}
      </button>
    </div>
  );
}

function FileRow({ file, subtitle }) {
  const [state, setState] = useState(null); // {kind, text, url, preview}

  useEffect(() => () => state?.url && URL.revokeObjectURL(state.url), [state]);

  const fetchAndVerify = async () => {
    setState({ kind: "info", text: "Downloading…" });
    try {
      const res = await api(`/api/files/${file.file_id}`, { raw: true });
      const buf = await res.arrayBuffer();
      const received = await sha256Hex(buf);
      const original = res.headers.get("X-File-SHA256");
      const url = URL.createObjectURL(new Blob([buf], { type: file.mime_type }));
      const preview = IMAGE_TYPES.includes(file.mime_type);
      if (received === null) {
        setState({ kind: "info", text: "Server verified SHA-256. Browser verification needs HTTPS.", url, preview });
        return;
      }
      if (received !== original || received !== file.sha256) {
        URL.revokeObjectURL(url);
        await api(`/api/files/${file.file_id}/integrity-report`, { method: "POST", body: { client_sha256: received } }).catch(() => {});
        setState({ kind: "error", text: "Integrity verification failed. File unavailable. Security event recorded." });
        return;
      }
      setState({ kind: "ok", text: "Integrity Verified ✓ (SHA-256 matches original)", url, preview });
    } catch (err) {
      setState({ kind: "error", text: err.message, retry: err.status === 0 });
    }
  };

  return (
    <div className="file-row">
      <div className="file-main">
        <div>
          <strong className="file-name">{file.filename}</strong>
          {file.status === "integrity_failed" && <span className="badge danger">integrity failed</span>}
        </div>
        <div className="muted small">
          {subtitle} · {formatSize(file.size)} · {file.mime_type.split("/").pop()} · v{file.version}
        </div>
        <div className="muted small mono" title={file.sha256}>
          SHA-256 {file.sha256.slice(0, 24)}…
        </div>
        <FileAddress fileId={file.file_id} />
      </div>
      <div className="file-actions">
        {!state?.url && (
          <button className="primary" onClick={fetchAndVerify} disabled={state?.kind === "info"}>
            {state?.retry ? "Retry" : "Download"}
          </button>
        )}
        {state?.url && (
          <a className="button primary" href={state.url} download={file.filename}>
            Save file
          </a>
        )}
      </div>
      {state && <div className={`alert ${state.kind} full`}>{state.text}</div>}
      {state?.preview && <img className="preview" src={state.url} alt={file.filename} />}
    </div>
  );
}
