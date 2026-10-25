"""API/data facade for CloudGuard V2. GET endpoints read saved data; POST scan runs a scan."""
from v2_scanner import run_v2_scan
from scan_history import (
    init_db, save_scan, get_latest_scan, get_scan_history,
    get_finding_history, get_alerts, acknowledge_alert,
)


def ensure_initial_scan():
    init_db()
    if get_latest_scan() is None:
        result = run_v2_scan()
        save_scan(result, scan_type="initial")


def run_and_save_v2_scan(scan_type="manual"):
    result = run_v2_scan()
    result["scan_type"] = scan_type
    result["scan_id"] = save_scan(result, scan_type=scan_type)
    # Ensure response includes timestamp from the persisted scan.
    latest = get_latest_scan()
    if latest:
        result["scanned_at"] = latest.get("scanned_at")
        result["scan_id"] = latest.get("id")
    return result


def get_v2_dashboard_data():
    """Return latest persisted scan without triggering another scan."""
    ensure_initial_scan()
    result = get_latest_scan()
    if result is None:
        return run_and_save_v2_scan("initial")
    return result


def get_v2_history(limit=25):
    return get_scan_history(limit)


def get_v2_finding_history(status=None, limit=200):
    return get_finding_history(status, limit)


def get_v2_alerts(limit=100, unacknowledged_only=False):
    return get_alerts(limit, unacknowledged_only)


def acknowledge_v2_alert(alert_id):
    return acknowledge_alert(alert_id)
