"""Internal text messaging (FR-12). Message bodies are AES-GCM encrypted at rest."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import audit, config
from ..db import get_db, now_iso
from ..security import crypto
from ..security.rbac import require

router = APIRouter(prefix="/api/messages", tags=["messages"])


class MessageIn(BaseModel):
    recipient_id: str = Field(min_length=1, max_length=64)
    content: str = Field(min_length=1, max_length=config.MAX_MESSAGE_CHARS)


def _aad(sender, recipient, sent_at):
    return f"msg|{sender}|{recipient}|{sent_at}".encode()


def _active_user(conn, user_id):
    return conn.execute("SELECT 1 FROM users WHERE user_id = ? AND status = 'active'", (user_id,)).fetchone()


@router.post("")
def send(body: MessageIn, request: Request, user=Depends(require("send_message")), conn=Depends(get_db)):
    if body.recipient_id == user["user_id"] or not _active_user(conn, body.recipient_id):
        audit.log_event(conn, "ACCESS_DENIED", "DENIED", request, details="invalid message recipient")
        raise HTTPException(400, "Recipient is not an active company user")
    sent_at = now_iso()
    ciphertext = crypto.encrypt(body.content.encode(), _aad(user["user_id"], body.recipient_id, sent_at))
    message_id = conn.execute(
        "INSERT INTO messages (sender_id, recipient_id, ciphertext, sent_at) VALUES (?, ?, ?, ?)",
        (user["user_id"], body.recipient_id, ciphertext, sent_at),
    ).lastrowid
    return {"message_id": message_id, "sent_at": sent_at, "delivery_status": "sent"}


@router.get("/unread")
def unread(user=Depends(require("send_message")), conn=Depends(get_db)):
    """Polled in the background. Fetching marks new incoming messages as 'delivered'."""
    conn.execute(
        "UPDATE messages SET delivery_status = 'delivered' WHERE recipient_id = ? AND delivery_status = 'sent'",
        (user["user_id"],),
    )
    rows = conn.execute(
        """SELECT sender_id, COUNT(*) AS unread FROM messages
           WHERE recipient_id = ? AND delivery_status != 'read' GROUP BY sender_id""",
        (user["user_id"],),
    ).fetchall()
    return {r["sender_id"]: r["unread"] for r in rows}


@router.get("")
def conversation(with_user: str, user=Depends(require("send_message")), conn=Depends(get_db)):
    """Messages between the caller and `with_user`. Opening the conversation marks incoming as read."""
    me = user["user_id"]
    conn.execute(
        "UPDATE messages SET delivery_status = 'read' WHERE recipient_id = ? AND sender_id = ?",
        (me, with_user),
    )
    rows = conn.execute(
        """SELECT * FROM messages
           WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
           ORDER BY message_id DESC LIMIT 200""",
        (me, with_user, with_user, me),
    ).fetchall()
    out = []
    for r in reversed(rows):
        try:
            content = crypto.decrypt(r["ciphertext"], _aad(r["sender_id"], r["recipient_id"], r["sent_at"])).decode()
        except crypto.InvalidTag:
            content = "[message failed integrity verification]"
        out.append({
            "message_id": r["message_id"], "sender_id": r["sender_id"], "recipient_id": r["recipient_id"],
            "sent_at": r["sent_at"], "delivery_status": r["delivery_status"], "content": content,
        })
    return out
