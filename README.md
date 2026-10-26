# Vishanti Ledger 🛡️
**Tamper-Evident Redressal and Grievance Ledger built with FastAPI, SQLite WAL mode, and SHA-256 Hash Chaining[cite: 9, 10].**

## Features
- **Structured Ticket Intake**: Anonymous filing, priority tiers, and automated SLA calculation[cite: 9, 10].
- **Deterministic State Machine**: Role-guarded status transitions enforced on the server[cite: 10].
- **SHA-256 Hash-Chained Audit Trail**: Every status change and comment is cryptographically chained, with database triggers preventing updates or deletions[cite: 10, 11].
- **Verify Ledger API**: Recomputes cryptographic hashes to instantly detect any database tampering[cite: 10, 11].

## Running Locally
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   