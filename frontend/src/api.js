// Thin fetch wrapper: same-origin cookies, JSON bodies, and the failure messages from PRD section 32.

// All tabs of one browser share the session cookie. Writing this key fires a `storage` event in the
// other tabs, so they reload the current user after a login or logout elsewhere.
export const AUTH_EVENT_KEY = "securelink.auth";
export function broadcastAuthChange() {
  try {
    localStorage.setItem(AUTH_EVENT_KEY, `${Date.now()}-${Math.random()}`);
  } catch {
    /* storage unavailable: other tabs will notice on their next 401 */
  }
}

let onSessionExpired = () => {};
export function setSessionExpiredHandler(fn) {
  onSessionExpired = fn;
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export const NETWORK_ERROR = "Transfer interrupted. Retry available.";

/**
 * @param {string} path
 * @param {{method?: string, body?: any, background?: boolean, raw?: boolean, quiet401?: boolean}} opts
 *   background: polling request; the server does not count it as user activity (inactivity timeout)
 *   raw: return the Response instead of parsed JSON
 *   quiet401: do not trigger the "session expired" handler (used for the initial /me check and login)
 */
export async function api(path, { method = "GET", body, background = false, raw = false, quiet401 = false } = {}) {
  const headers = {};
  if (background) headers["X-Background"] = "1";
  let payload = body;
  if (body !== undefined && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(path, { method, headers, body: payload, credentials: "same-origin" });
  } catch {
    throw new ApiError(0, NETWORK_ERROR);
  }

  if (res.status === 401 && !quiet401) {
    onSessionExpired();
    throw new ApiError(401, "Session expired. Please log in again");
  }
  if (!res.ok) {
    let message = res.statusText || `Error ${res.status}`;
    try {
      const detail = (await res.json()).detail;
      if (typeof detail === "string") message = detail;
      else if (Array.isArray(detail) && detail[0]?.msg) {
        // FastAPI validation error: name the field and avoid showing raw regex patterns
        const field = String(detail[0].loc?.at(-1) ?? "input").replaceAll("_", " ");
        const reason = detail[0].type === "string_pattern_mismatch" ? "contains characters that are not allowed" : detail[0].msg;
        message = `Invalid ${field}: ${reason}`;
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message);
  }
  return raw ? res : res.json();
}

// WebCrypto only exists in secure contexts (HTTPS or localhost). Returns null in the lab-only
// plaintext HTTP mode, where the server then skips the client-hash comparison.
export async function sha256Hex(buffer) {
  if (!globalThis.crypto?.subtle) return null;
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16)); // available in insecure contexts too
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Random per-browser identifier used for the two-device session limit.
export function deviceId() {
  const KEY = "securelink.device_id";
  try {
    let id = localStorage.getItem(KEY);
    if (!id) {
      id = randomId();
      localStorage.setItem(KEY, id);
    }
    return id;
  } catch {
    return randomId();
  }
}

export function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function formatTime(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}
