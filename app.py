from v2_api import (
    get_v2_dashboard_data,
    run_and_save_v2_scan,
    get_v2_history,
    get_v2_finding_history,
    get_v2_alerts,
    acknowledge_v2_alert,
)
from monitoring import start_monitor, run_scan_safely
from flask import request, jsonify, render_template
from flask import Flask, render_template, jsonify, request
import json

# V1 imports: keep these files in your original CloudGuard project.
from scanner import run_scan, calculate_security_score

# V2 imports: copy the V2 backend files into the same folder as app.py.
from v2_api import (
    get_v2_dashboard_data,
    get_v2_history,
    get_v2_finding_history,
    get_v2_alerts,
    acknowledge_v2_alert,
)
from monitoring import start_monitor, run_scan_safely

app = Flask(__name__)


# -----------------------------
# V1 BACKEND (preserved)
# -----------------------------
def get_resources():
    with open("config.json", "r", encoding="utf-8") as file:
        data = json.load(file)

    resources = data["resources"]
    findings = run_scan()
    risky_resources = {finding["resource"] for finding in findings}

    for resource in resources:
        resource["status"] = (
            "AT RISK" if resource["name"] in risky_resources else "SECURE"
        )

    return resources


def get_dashboard_data():
    findings = run_scan()
    security_score = calculate_security_score(findings)

    severity_counts = {
        severity: sum(1 for finding in findings if finding.get("severity") == severity)
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    resources = get_resources()
    secure_resources = sum(1 for resource in resources if resource["status"] == "SECURE")
    risky_resources = sum(1 for resource in resources if resource["status"] == "AT RISK")

    return {
        "security_score": security_score,
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],
        "secure_resources": secure_resources,
        "risky_resources": risky_resources,
        "resources": resources,
        "findings": findings,
    }


@app.route("/")
def dashboard():
    # Preserve the existing homepage template from your original project.
    data = get_dashboard_data()
    return render_template("v2_dashboard.html", **data)


@app.route("/api/dashboard-data")
def dashboard_data():
    return jsonify(get_dashboard_data())


@app.route("/api/scan", methods=["POST"])
def scan():
    data = get_dashboard_data()
    return jsonify({"success": True, **data})


@app.route("/security-scan")
def security_scan():
    return render_template("security_scan.html")


# -----------------------------
# V2 BACKEND (added, theme unchanged)
# -----------------------------
@app.route("/v2")
def v2_dashboard():
    data = get_v2_dashboard_data()
    return render_template("v2_dashboard.html", **data)
# ---------- CloudGuard V2 API ----------

@app.route("/api/v2/dashboard-data")
def v2_dashboard_data():
    return jsonify(get_v2_dashboard_data())


@app.route("/api/v2/scan", methods=["POST"])
def v2_scan():
    return jsonify(run_scan_safely("manual"))


@app.route("/api/v2/history")
def v2_history():
    limit = request.args.get("limit", default=25, type=int)
    return jsonify({"history": get_v2_history(limit)})


@app.route("/api/v2/findings/history")
def v2_findings_history():
    status = request.args.get("status")
    limit = request.args.get("limit", default=200, type=int)
    return jsonify({
        "findings": get_v2_finding_history(status, limit)
    })


@app.route("/api/v2/alerts")
def v2_alerts():
    limit = request.args.get("limit", default=100, type=int)
    return jsonify({"alerts": get_v2_alerts(limit)})


@app.route("/v2/security-scan")
def v2_security_scan():
    return render_template(
        "v2_security_scan.html",
        **get_v2_dashboard_data()
    )


@app.route("/v2/findings")
def v2_findings():
    return render_template(
        "v2_findings.html",
        **get_v2_dashboard_data()
    )


@app.route("/v2/resources")
def v2_resources():
    return render_template(
        "v2_resources.html",
        **get_v2_dashboard_data()
    )


@app.route("/report")
def v2_report():
    return render_template(
        "v2_report.html",
        **get_v2_dashboard_data()
    )

if __name__ == "__main__":
    start_monitor(interval_seconds=60)
    app.run(debug=True, use_reloader=False)