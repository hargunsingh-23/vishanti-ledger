import sqlite3
import hashlib
import json
import os
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Form, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import bcrypt

DB_FILE = "ledger.db"

app = FastAPI(title="Vishanti Ledger")

# --- DATABASE SETUP & APPEND-ONLY TRIGGERS ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL;")
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL, -- petitioner, official, admin
            password_hash TEXT NOT NULL
        )
    """)

    # Tickets Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            description TEXT NOT NULL,
            petitioner_id INTEGER,
            assigned_official_id INTEGER,
            tracking_code_hash TEXT,
            sla_due_at TEXT,
            created_at TEXT
        )
    """)

    # Audit Log Table (Hash Chained)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            payload TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            UNIQUE(ticket_id, seq)
        )
    """)

    # Immutable Audit Log Trigger (Prevents UPDATE or DELETE)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_tampering_update
        BEFORE UPDATE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'Audit log is immutable and append-only.');
        END;
    """)
    cursor.execute("""
        CREATE TRIGGER IF NOT EXISTS prevent_audit_tampering_delete
        BEFORE DELETE ON audit_log
        BEGIN
            SELECT RAISE(ABORT, 'Audit log is immutable and append-only.');
        END;
    """)

    conn.commit()
    conn.close()

init_db()

# --- STATE MACHINE & ROLE GUARDS ---
TRANSITIONS = {
    ("Filed", "Assigned"): ["admin"],
    ("Assigned", "In Review"): ["official"],
    ("In Review", "Resolved"): ["official"],
    ("Assigned", "Escalated"): ["admin", "official"],
    ("In Review", "Escalated"): ["admin", "official"],
    ("Resolved", "Escalated"): ["petitioner"],
    ("Escalated", "Assigned"): ["admin"]
}

def validate_transition(current_status: str, new_status: str, role: str):
    allowed_roles = TRANSITIONS.get((current_status, new_status))
    if not allowed_roles or role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Illegal transition from {current_status} to {new_status} for role {role}")

# --- HASH CHAIN HELPER ---
def append_audit_entry(ticket_id: int, actor: str, action: str, payload: dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Get last sequence and hash for this ticket
    cursor.execute("SELECT seq, entry_hash FROM audit_log WHERE ticket_id = ? ORDER BY seq DESC LIMIT 1", (ticket_id,))
    last = cursor.fetchone()

    if last is None:
        seq = 1
        prev_hash = "0" * 64
    else:
        seq = last[0] + 1
        prev_hash = last[1]

    payload_str = json.dumps(payload, sort_keys=True)
    hasher = hashlib.sha256()
    hasher.update((prev_hash + str(ticket_id) + str(seq) + actor + action + payload_str).encode('utf-8'))
    entry_hash = hasher.hexdigest()

    cursor.execute("""
        INSERT INTO audit_log (ticket_id, seq, actor, action, payload, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (ticket_id, seq, actor, action, payload_str, prev_hash, entry_hash))

    conn.commit()
    conn.close()

# --- ROUTES ---
@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <html>
        <head><title>Vishanti Ledger</title></head>
        <body style="font-family: Arial; padding: 40px; background: #0f172a; color: #f8fafc;">
            <h1>🛡️ Vishanti Ledger (Tamper-Evident Redressal Portal)</h1>
            <p>Welcome to the secure grievance tracking system backed by SHA-256 hash chains.</p>
            <ul>
                <li><a href="/docs" style="color: #38bdf8;">API Documentation (Swagger UI)</a></li>
                <li><a href="/tickets" style="color: #38bdf8;">View All Tickets</a></li>
            </ul>
        </body>
    </html>
    """

@app.get("/tickets")
def list_tickets():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    tickets = conn.execute("SELECT * FROM tickets").fetchall()
    conn.close()
    return [dict(t) for t in tickets]

@app.post("/tickets")
def file_ticket(category: str = Form(...), priority: str = Form(...), description: str = Form(...), petitioner_name: str = Form("Anonymous")):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    now = datetime.utcnow().isoformat()
    sla_due = (datetime.utcnow() + timedelta(hours=24)).isoformat() # Example 24h SLA
    
    cursor.execute("""
        INSERT INTO tickets (category, priority, status, description, petitioner_id, sla_due_at, created_at)
        VALUES (?, ?, 'Filed', ?, NULL, ?, ?)
    """, (category, priority, description, sla_due, now))
    
    ticket_id = cursor.lastrowid
    conn.commit()
    conn.close()

    # Record first audit entry
    append_audit_entry(ticket_id, actor=petitioner_name, action="FILE_TICKET", payload={"category": category, "priority": priority})

    return {"message": "Ticket filed successfully", "ticket_id": ticket_id, "status": "Filed"}

@app.get("/tickets/{ticket_id}/verify")
def verify_ledger(ticket_id: int):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    entries = conn.execute("SELECT * FROM audit_log WHERE ticket_id = ? ORDER BY seq ASC", (ticket_id,)).fetchall()
    conn.close()

    if not entries:
        raise HTTPException(status_code=404, detail="No audit trail found for this ticket.")

    prev_hash = "0" * 64
    for entry in entries:
        if entry["prev_hash"] != prev_hash:
            return {"verified": False, "broken_at_seq": entry["seq"], "reason": "Previous hash mismatch (Tampering detected!)"}
        
        payload_str = entry["payload"]
        hasher = hashlib.sha256()
        hasher.update((prev_hash + str(ticket_id) + str(entry["seq"]) + entry["actor"] + entry["action"] + payload_str).encode('utf-8'))
        computed_hash = hasher.hexdigest()

        if computed_hash != entry["entry_hash"]:
            return {"verified": False, "broken_at_seq": entry["seq"], "reason": "Entry hash mismatch (Data modified!)"}

        prev_hash = computed_hash

    return {"verified": True, "total_entries": len(entries), "head_hash": prev_hash}