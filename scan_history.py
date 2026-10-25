"""Persistent scan history, resource snapshots, finding lifecycle, and alerts for CloudGuard V2."""
from __future__ import annotations
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().with_name("cloudguard_history.db")
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def utc_now():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _connect():
    connection = sqlite3.connect(DB_PATH, timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with _connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            security_score INTEGER NOT NULL,
            total_resources INTEGER NOT NULL,
            total_checks INTEGER NOT NULL,
            passed_checks INTEGER NOT NULL,
            failed_checks INTEGER NOT NULL,
            critical INTEGER NOT NULL,
            high INTEGER NOT NULL,
            medium INTEGER NOT NULL,
            low INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS check_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            resource_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            policy TEXT NOT NULL,
            passed INTEGER NOT NULL,
            severity TEXT NOT NULL,
            issue TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            scanned_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS resource_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            resource_id TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            provider TEXT NOT NULL,
            region TEXT NOT NULL,
            status TEXT NOT NULL,
            last_scanned_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS finding_history (
            finding_key TEXT PRIMARY KEY,
            resource_id TEXT NOT NULL,
            resource TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            policy TEXT NOT NULL,
            issue TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT,
            status TEXT NOT NULL CHECK(status IN ('OPEN','RESOLVED'))
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            resource TEXT NOT NULL,
            policy TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            acknowledged INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC);
        CREATE INDEX IF NOT EXISTS idx_checks_scan_id ON check_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_resources_scan_id ON resource_snapshots(scan_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
        """)


def _finding_key(finding):
    # Stable across scans: do not use issue text or severity because they may change.
    return f"{finding.get('resource_id', finding.get('resource', 'unknown'))}::{finding.get('policy', 'unknown')}"


def save_scan(result, scan_type="manual"):
    """Persist one complete scan atomically and emit alerts only on state transitions."""
    init_db()
    scanned_at = utc_now()
    resources = result.get("resources", [])
    checks = result.get("checks", [])
    findings = result.get("findings", [])
    counts = result.get("severity_counts", {})

    with _connect() as db:
        db.execute("BEGIN IMMEDIATE")
        cursor = db.execute("""INSERT INTO scans
            (scanned_at, scan_type, security_score, total_resources, total_checks,
             passed_checks, failed_checks, critical, high, medium, low)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scanned_at, scan_type, int(result.get("security_score", 100)), len(resources),
             int(result.get("total_checks", len(checks))), int(result.get("passed_checks", 0)),
             int(result.get("failed_checks", len(findings))), int(counts.get("critical", 0)),
             int(counts.get("high", 0)), int(counts.get("medium", 0)), int(counts.get("low", 0))))
        scan_id = cursor.lastrowid

        for check in checks:
            db.execute("""INSERT INTO check_results
                (scan_id, resource_id, resource, resource_type, policy, passed, severity,
                 issue, description, recommendation, scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, str(check.get("resource_id", "")), check.get("resource", "Unknown"),
                 check.get("resource_type", "unknown"), check.get("policy", "Unknown policy"),
                 1 if check.get("passed") else 0, check.get("severity", "LOW"),
                 check.get("issue", "No issue"), check.get("description", ""),
                 check.get("recommendation", ""), scanned_at))

        risky_names = {f.get("resource") for f in findings}
        for resource in resources:
            status = "AT RISK" if resource.get("name") in risky_names else "SECURE"
            db.execute("""INSERT INTO resource_snapshots
                (scan_id, resource_id, name, type, provider, region, status, last_scanned_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, str(resource.get("id", "")), resource.get("name", "Unknown"),
                 resource.get("type", "unknown"), resource.get("provider", "CloudGuard-Cloud"),
                 resource.get("region", "Unknown"), status, scanned_at))

        prior_rows = db.execute("SELECT * FROM finding_history WHERE status='OPEN'").fetchall()
        prior_open = {row["finding_key"]: dict(row) for row in prior_rows}
        current = {_finding_key(f): f for f in findings}

        def alert(alert_type, finding, message):
            db.execute("""INSERT INTO alerts
                (scan_id, alert_type, severity, resource, policy, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (scan_id, alert_type, finding.get("severity", "LOW"), finding.get("resource", "Unknown"),
                 finding.get("policy", "Unknown policy"), message, scanned_at))

        # New findings, reopened findings, and severity increases.
        for key, finding in current.items():
            existing = db.execute("SELECT * FROM finding_history WHERE finding_key=?", (key,)).fetchone()
            if key not in prior_open:
                if existing is None:
                    alert("NEW_FINDING", finding, f"New {finding.get('severity', 'LOW')} risk: {finding.get('issue', finding.get('policy', 'Security issue'))} on {finding.get('resource', 'resource')}.")
                    db.execute("""INSERT INTO finding_history
                        (finding_key, resource_id, resource, resource_type, policy, issue, severity,
                         description, recommendation, first_seen, last_seen, resolved_at, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'OPEN')""",
                        (key, str(finding.get("resource_id", "")), finding.get("resource", "Unknown"),
                         finding.get("resource_type", "unknown"), finding.get("policy", "Unknown policy"),
                         finding.get("issue", "Security issue"), finding.get("severity", "LOW"),
                         finding.get("description", ""), finding.get("recommendation", ""), scanned_at, scanned_at))
                else:
                    # Previously resolved: reopen and create one new transition alert.
                    alert("REOPENED_FINDING", finding, f"Risk reappeared: {finding.get('issue', finding.get('policy', 'Security issue'))} on {finding.get('resource', 'resource')}.")
                    db.execute("""UPDATE finding_history SET resource_id=?, resource=?, resource_type=?, policy=?,
                        issue=?, severity=?, description=?, recommendation=?, last_seen=?, resolved_at=NULL, status='OPEN'
                        WHERE finding_key=?""",
                        (str(finding.get("resource_id", "")), finding.get("resource", "Unknown"),
                         finding.get("resource_type", "unknown"), finding.get("policy", "Unknown policy"),
                         finding.get("issue", "Security issue"), finding.get("severity", "LOW"),
                         finding.get("description", ""), finding.get("recommendation", ""), scanned_at, key))
            else:
                old = prior_open[key]
                if SEVERITY_RANK.get(finding.get("severity", "LOW"), 1) > SEVERITY_RANK.get(old.get("severity", "LOW"), 1):
                    alert("SEVERITY_INCREASED", finding, f"Severity increased to {finding.get('severity')}: {finding.get('issue', finding.get('policy', 'Security issue'))} on {finding.get('resource', 'resource')}.")
                db.execute("""UPDATE finding_history SET resource_id=?, resource=?, resource_type=?, policy=?,
                    issue=?, severity=?, description=?, recommendation=?, last_seen=?, status='OPEN', resolved_at=NULL
                    WHERE finding_key=?""",
                    (str(finding.get("resource_id", "")), finding.get("resource", "Unknown"),
                     finding.get("resource_type", "unknown"), finding.get("policy", "Unknown policy"),
                     finding.get("issue", "Security issue"), finding.get("severity", "LOW"),
                     finding.get("description", ""), finding.get("recommendation", ""), scanned_at, key))

        # Findings that disappeared are resolved, not deleted.
        for key, old in prior_open.items():
            if key not in current:
                db.execute("UPDATE finding_history SET status='RESOLVED', resolved_at=?, last_seen=? WHERE finding_key=?",
                           (scanned_at, scanned_at, key))
                alert("RESOLVED_FINDING", old, f"Risk resolved: {old.get('issue', old.get('policy', 'Security issue'))} on {old.get('resource', 'resource')}.")

        return scan_id


def _scan_dict(row):
    return dict(row) if row else None


def get_latest_scan():
    init_db()
    with _connect() as db:
        row = db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        scan = dict(row)
        scan_id = scan["id"]
        scan["resources"] = [dict(r) for r in db.execute("SELECT resource_id AS id, name, type, provider, region, status, last_scanned_at FROM resource_snapshots WHERE scan_id=? ORDER BY name", (scan_id,))]
        scan["checks"] = [dict(r) for r in db.execute("SELECT resource_id, resource, resource_type, policy, passed, severity, issue, description, recommendation, scanned_at FROM check_results WHERE scan_id=? ORDER BY resource, policy", (scan_id,))]
        scan["findings"] = []
        for check in scan["checks"]:
            if not check["passed"]:
                scan["findings"].append({"resource_id": check["resource_id"], "resource": check["resource"], "resource_type": check["resource_type"], "policy": check["policy"], "issue": check["issue"], "severity": check["severity"], "description": check["description"], "recommendation": check["recommendation"]})
        scan["severity_counts"] = {"critical": scan["critical"], "high": scan["high"], "medium": scan["medium"], "low": scan["low"]}
        scan["total_findings"] = len(scan["findings"])
        scan["secure_resources"] = sum(1 for r in scan["resources"] if r["status"] == "SECURE")
        scan["risky_resources"] = sum(1 for r in scan["resources"] if r["status"] == "AT RISK")
        return scan


def get_scan_history(limit=25):
    init_db()
    with _connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 200)),))]


def get_finding_history(status=None, limit=200):
    init_db()
    with _connect() as db:
        if status in ("OPEN", "RESOLVED"):
            rows = db.execute("SELECT * FROM finding_history WHERE status=? ORDER BY last_seen DESC LIMIT ?", (status, max(1, min(int(limit), 1000)))).fetchall()
        else:
            rows = db.execute("SELECT * FROM finding_history ORDER BY last_seen DESC LIMIT ?", (max(1, min(int(limit), 1000)),)).fetchall()
        return [dict(r) for r in rows]


def get_alerts(limit=100, unacknowledged_only=False):
    init_db()
    with _connect() as db:
        sql = "SELECT * FROM alerts"
        if unacknowledged_only:
            sql += " WHERE acknowledged=0"
        sql += " ORDER BY id DESC LIMIT ?"
        return [dict(r) for r in db.execute(sql, (max(1, min(int(limit), 500)),))]


def acknowledge_alert(alert_id):
    init_db()
    with _connect() as db:
        cur = db.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (int(alert_id),))
        return cur.rowcount > 0
