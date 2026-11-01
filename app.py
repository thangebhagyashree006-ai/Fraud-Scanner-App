from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
import os
import re
import secrets

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
CORS(app)

# Demo in-memory storage. Data is lost when the server restarts.
users_data = {}
scan_history = []
fraud_reports = []
blog_posts = []


class FraudAnalyzer:
    def __init__(self):
        self.suspicious_keywords = [
            "urgent", "act now", "limited time", "click here",
            "verify account", "suspended", "bitcoin", "cryptocurrency",
            "investment opportunity", "free money", "tax refund",
            "winner", "congratulations", "inheritance", "prince",
            "lottery", "sweepstakes", "money transfer", "wire transfer"
        ]
        self.phishing_indicators = [
            "login", "password", "social security", "bank account",
            "credit card", "paypal", "amazon", "microsoft", "google",
            "apple", "secure", "verify identity", "update payment",
            "account locked"
        ]
        self.url_red_flags = [
            "bit.ly", "tinyurl", "shortened", "suspicious-domain",
            "phishing", "fake", "scam", "fraud"
        ]

    def analyze_url(self, url):
        score, details = 0, []
        parsed_url = urlparse(url.strip().lower())
        if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
            return 80, ["Invalid or incomplete URL format"]
        domain = parsed_url.hostname or ""
        if domain.endswith((".tk", ".ml", ".ga", ".cf", ".ru", ".cc")):
            score += 25
            details.append("Suspicious top-level domain detected")
        if any(domain == item or domain.endswith("." + item)
               for item in ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly")):
            score += 15
            details.append("URL shortener detected - be cautious")
        if domain.count(".") > 2:
            score += 10
            details.append("Multiple subdomains detected")
        if parsed_url.scheme != "https":
            score += 20
            details.append("Not using secure HTTPS protocol")
        for keyword in self.url_red_flags:
            if keyword in url.lower():
                score += 30
                details.append(f"Suspicious keyword '{keyword}' found in URL")
        if not details:
            details.append("No configured URL warning indicators were detected")
        return min(score, 100), details

    def analyze_email(self, email_content, sender_email=""):
        score, details = 0, []
        content_lower = email_content.lower()
        suspicious_count = sum(1 for word in self.suspicious_keywords if word in content_lower)
        score += min(suspicious_count * 5, 30)
        if suspicious_count:
            details.append(f"Found {suspicious_count} suspicious keywords")
        phishing_count = sum(1 for word in self.phishing_indicators if word in content_lower)
        score += min(phishing_count * 8, 40)
        if phishing_count:
            details.append(f"Found {phishing_count} phishing indicators")
        urgency_count = sum(1 for word in ["urgent", "immediate", "expire", "suspend", "act now"]
                             if word in content_lower)
        score += min(urgency_count * 10, 25)
        if urgency_count:
            details.append("Uses urgent language to pressure action")
        if sender_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", sender_email):
            score += 5
            details.append("Sender email address has an unusual format")
        if not details:
            details.append("No configured email warning indicators were detected")
        return min(score, 100), details

    def analyze_message(self, message):
        score, details = 0, []
        message_lower = message.lower()
        suspicious_count = sum(1 for word in self.suspicious_keywords if word in message_lower)
        score += min(suspicious_count * 7, 35)
        if suspicious_count:
            details.append(f"Contains {suspicious_count} suspicious terms")
        urls = re.findall(r"https?://[^\s<>'\"]+", message)
        if urls:
            score += 20
            details.append(f"Contains {len(urls)} links - verify before clicking")
        personal_count = sum(1 for item in ["password", "ssn", "social security", "bank account", "pin"]
                             if item in message_lower)
        if personal_count:
            score += 25
            details.append("Requests personal/sensitive information")
        if not details:
            details.append("No configured message warning indicators were detected")
        return min(score, 100), details

    @staticmethod
    def get_risk_level(score):
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"


analyzer = FraudAnalyzer()


def get_json_data():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def get_recommendations(risk_level):
    recommendations = {
        "critical": ["Do not interact with this content.", "Do not provide personal or financial information.",
                     "Report the incident through official channels.", "Block the sender or website if appropriate."],
        "high": ["Exercise extreme caution.", "Verify the source through official channels.",
                 "Do not click links or open unexpected attachments.", "Ask a trusted person or security professional for advice."],
        "medium": ["Double-check the source.", "Verify using official contact details.",
                   "Do not rush into taking action.", "Avoid sharing sensitive information."],
        "low": ["No major configured warning indicators were detected.",
                "Still verify important information independently.", "Continue following good security practices."]
    }
    return recommendations[risk_level]


@app.route("/test")
def test():
    return "Flask is working! Server is running properly."


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_content():
    data = get_json_data()
    content = str(data.get("content", "")).strip()
    scan_type = str(data.get("type", "message")).lower().strip()
    if not content:
        return jsonify({"error": "Content is required"}), 400
    if scan_type == "url":
        fraud_score, details = analyzer.analyze_url(content)
    elif scan_type == "email":
        fraud_score, details = analyzer.analyze_email(content, str(data.get("sender", "")).strip())
    elif scan_type == "message":
        fraud_score, details = analyzer.analyze_message(content)
    else:
        return jsonify({"error": "Type must be url, email, or message"}), 400
    risk_level = analyzer.get_risk_level(fraud_score)
    scan_id = len(scan_history) + 1
    scan_history.append({
        "id": scan_id, "content": content[:500], "scan_type": scan_type,
        "fraud_score": fraud_score, "risk_level": risk_level,
        "timestamp": datetime.now().isoformat(), "ip_address": request.remote_addr,
        "details": details
    })
    return jsonify({"fraud_score": fraud_score, "risk_level": risk_level, "details": details,
                    "recommendations": get_recommendations(risk_level), "scan_id": scan_id})


@app.route("/api/history")
def get_history():
    return jsonify(scan_history[-10:][::-1])


@app.route("/api/alerts")
def get_fraud_alerts():
    return jsonify([
        {"type": "UPI Scam", "location": "Mumbai", "count": 15, "latest_report": datetime.now().isoformat()},
        {"type": "Phishing Email", "location": "Delhi", "count": 23, "latest_report": datetime.now().isoformat()},
        {"type": "Investment Fraud", "location": "Bangalore", "count": 8, "latest_report": datetime.now().isoformat()}
    ])


@app.route("/api/report", methods=["POST"])
def submit_report():
    data = get_json_data()
    required = ["title", "description", "fraud_type", "location"]
    missing = [field for field in required if not str(data.get(field, "")).strip()]
    if missing:
        return jsonify({"error": "Missing required fields", "fields": missing}), 400
    try:
        amount_lost = float(data.get("amount_lost", 0) or 0)
        if amount_lost < 0:
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "amount_lost must be a non-negative number"}), 400
    report_id = len(fraud_reports) + 1
    fraud_reports.append({
        "id": report_id, "title": str(data["title"]).strip(),
        "description": str(data["description"]).strip(), "fraud_type": str(data["fraud_type"]).strip(),
        "location": str(data["location"]).strip(), "amount_lost": amount_lost,
        "report_date": datetime.now().isoformat(), "status": "pending",
        "is_anonymous": bool(data.get("anonymous", False))
    })
    return jsonify({"message": "Report submitted successfully", "report_id": report_id}), 201


@app.route("/api/register", methods=["POST"])
def register():
    data = get_json_data()
    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not username or not email or not password:
        return jsonify({"error": "Username, email, and password are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must contain at least 8 characters"}), 400
    if username in users_data:
        return jsonify({"error": "Username already exists"}), 400
    if any(user["email"] == email for user in users_data.values()):
        return jsonify({"error": "Email already registered"}), 400
    user_id = len(users_data) + 1
    users_data[username] = {"id": user_id, "username": username, "email": email,
                            "password_hash": generate_password_hash(password),
                            "created_at": datetime.now().isoformat()}
    session.clear()
    session["user_id"] = user_id
    session["username"] = username
    return jsonify({"message": "Registration successful", "user_id": user_id}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = get_json_data()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    user = users_data.get(username)
    if user and check_password_hash(user["password_hash"], password):
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return jsonify({"message": "Login successful", "user_id": user["id"]})
    return jsonify({"error": "Invalid username or password"}), 401


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"})


@app.route("/api/stats")
def get_stats():
    total = len(scan_history)
    return jsonify({"total_scans": total, "total_reports": len(fraud_reports),
                    "high_risk_scans": sum(1 for item in scan_history if item["risk_level"] in ("high", "critical")),
                    "recent_scans": total, "fraud_prevented": "Not available"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
