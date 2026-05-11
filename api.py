"""
Flask REST API wrapping password_check.py.
Run:  pip install flask flask-cors
      python api.py
"""

from flask import Flask, jsonify, request
from flask_cors import CORS

from password_check import analyse

app = Flask(__name__)
CORS(app)


@app.route("/api/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400

    report = analyse(password, skip_hibp=data.get("no_hibp", False))
    return jsonify({
        "score":          report.score,
        "entropy_bits":   round(report.entropy_bits, 2),
        "crack_time":     report.crack_time,
        "critical_count": report.critical_count,
        "warning_count":  report.warning_count,
        "suggestion":     report.suggestion if (report.critical_count or report.warning_count) else None,
        "checks": [
            {
                "name":     c.name,
                "passed":   c.passed,
                "severity": c.severity,
                "message":  c.message,
            }
            for c in report.checks
        ],
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
