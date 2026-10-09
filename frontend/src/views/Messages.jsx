import { useCallback, useEffect, useRef, useState } from "react";
import { api, formatTime } from "../api.js";

const POLL_MS = 5000;
const STATUS_ICON = { sent: "✓", delivered: "✓✓", read: "✓✓ read" };

export default function Messages({ me }) {
  const [users, setUsers] = useState([]);
  const [unread, setUnread] = useState({});
  const [selected, setSelected] = useState(null);
  const [conversation, setConversation] = useState([]);
  const [text, setText] = useState("");
  const [error, setError] = useState("");
  const bottomRef = useRef(null);

  useEffect(() => {
    api("/api/users").then(setUsers).catch((e) => setError(e.message));
  }, []);

  const loadConversation = useCallback(
    (background) =>
      selected &&
      api(`/api/messages?with_user=${encodeURIComponent(selected.user_id)}`, { background })
        .then(setConversation)
        .catch((e) => setError(e.message)),
    [selected]
  );

  // Background polling: does not refresh the session's inactivity timer.
  useEffect(() => {
    const poll = () => {
      api("/api/messages/unread", { background: true }).then(setUnread).catch(() => {});
      loadConversation(true);
    };
    poll();
    const t = setInterval(poll, POLL_MS);
    return () => clearInterval(t);
  }, [loadConversation]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ block: "end" });
  }, [conversation.length]);

  const open = (u) => {
    setSelected(u);
    setConversation([]);
    setError("");
  };

  const send = async (e) => {
    e.preventDefault();
    if (!text.trim()) return;
    try {
      await api("/api/messages", { method: "POST", body: { recipient_id: selected.user_id, content: text } });
      setText("");
      loadConversation(false);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className={selected ? "chat has-selection" : "chat"}>
      <aside className="card people">
        <h2>Colleagues</h2>
        {users.length === 0 && <p className="muted">No other active users yet.</p>}
        {users.map((u) => (
          <button
            key={u.user_id}
            className={selected?.user_id === u.user_id ? "person active" : "person"}
            onClick={() => open(u)}
          >
            <span>
              <strong>{u.name}</strong>
              <span className="muted small">
                {" "}
                {u.department} · {u.role}
              </span>
            </span>
            {unread[u.user_id] > 0 && <span className="count">{unread[u.user_id]}</span>}
          </button>
        ))}
      </aside>

      <section className="card thread">
        {!selected ? (
          <p className="muted center">Select a colleague to start messaging.</p>
        ) : (
          <>
            <div className="thread-head">
              <button className="ghost back" onClick={() => setSelected(null)}>
                ← Back
              </button>
              <h2>{selected.name}</h2>
            </div>
            {error && <div className="alert error">{error}</div>}
            <div className="bubbles">
              {conversation.map((m) => {
                const mine = m.sender_id === me.user_id;
                return (
                  <div key={m.message_id} className={mine ? "bubble mine" : "bubble"}>
                    <div className="bubble-text">{m.content}</div>
                    <div className="bubble-meta">
                      {formatTime(m.sent_at)} {mine && <span title={m.delivery_status}>{STATUS_ICON[m.delivery_status]}</span>}
                    </div>
                  </div>
                );
              })}
              <div ref={bottomRef} />
            </div>
            <form className="composer" onSubmit={send}>
              <input
                value={text}
                onChange={(e) => setText(e.target.value)}
                placeholder="Type a message"
                maxLength={5000}
              />
              <button className="primary">Send</button>
            </form>
          </>
        )}
      </section>
    </div>
  );
}
