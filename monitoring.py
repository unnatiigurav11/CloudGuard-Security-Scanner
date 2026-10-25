"""Single-process background monitor for CloudGuard V2."""
import threading
import logging
from v2_api import run_and_save_v2_scan, ensure_initial_scan

logger = logging.getLogger(__name__)
_monitor_thread = None
_monitor_lock = threading.Lock()
_scan_lock = threading.Lock()
_stop_event = threading.Event()


def run_scan_safely(scan_type="manual"):
    # Prevent manual and automatic scans from overlapping in one process.
    with _scan_lock:
        return run_and_save_v2_scan(scan_type)


def _monitor_loop(interval_seconds):
    while not _stop_event.wait(interval_seconds):
        try:
            run_scan_safely("automatic")
        except Exception:
            logger.exception("CloudGuard automatic scan failed")


def start_monitor(interval_seconds=60):
    """Start one daemon monitor per Python process. Safe to call more than once."""
    global _monitor_thread
    with _monitor_lock:
        ensure_initial_scan()
        if _monitor_thread is not None and _monitor_thread.is_alive():
            return False
        _stop_event.clear()
        _monitor_thread = threading.Thread(
            target=_monitor_loop, args=(max(10, int(interval_seconds)),),
            name="CloudGuardV2Monitor", daemon=True,
        )
        _monitor_thread.start()
        return True


def stop_monitor():
    _stop_event.set()
