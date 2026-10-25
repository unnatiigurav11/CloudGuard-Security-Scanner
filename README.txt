CLOUDGUARD V2 BACKEND UPGRADE

What this upgrade adds
- SQLite history in cloudguard_history.db (created automatically beside app.py).
- Manual scans through POST /api/v2/scan.
- Automatic scans every 60 seconds while app.py is running.
- Saved per-policy pass/fail results and resource snapshots for each scan.
- Current open findings plus retained resolved finding history.
- Transition-only alerts: new finding, reopened finding, severity increase, resolved finding.
- Read endpoints: /api/v2/history, /api/v2/findings/history, /api/v2/alerts, /api/v2/check-results.
- Existing V1 routes are retained in app.py.

Important
- CloudGuard V2 continues to scan the local simulated resources in cloud_simulator.py. It does not connect to AWS/Azure/GCP.
- Back up your current project before replacing files.
- Copy app.py, v2_api.py, v2_scanner.py, and monitoring.py, scan_history.py into your project root.
- Keep cloud_simulator.py, policy_engine.py, resource_discovery.py, scanner.py, config.json, and your templates in their existing locations.
- The current policy engine is retained, so existing V2 rules remain the source of failed findings.
- Run `python v2_scanner.py` first to confirm the scanner output. Then run `python app.py`.
- Stop the Flask process to stop automatic monitoring. The monitor only runs while the backend process is active.

API quick checks
GET  /api/v2/dashboard-data
POST /api/v2/scan
GET  /api/v2/history
GET  /api/v2/check-results
GET  /api/v2/findings/history?status=OPEN
GET  /api/v2/findings/history?status=RESOLVED
GET  /api/v2/alerts
GET  /api/v2/alerts?unacknowledged=true
POST /api/v2/alerts/<alert_id>/acknowledge

Note: The frontend may need a small later adjustment to display alert/history panels. This backend exposes the data endpoints without requiring a dashboard theme change now.
