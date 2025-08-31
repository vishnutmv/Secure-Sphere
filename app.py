from flask import Flask, render_template, request, redirect, url_for, send_file, flash, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import socket
import re
import io
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///Secure Sphere.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
from plyer import notification

def send_system_alert(scan_target:str, impact:str):
    phrases = {
        "Critical": "🚨 Critical risk detected!",
        "High": "⚠️ High impact vulnerabilities!",
        "Medium": "⚠️ Moderate risk found.",
        "Low": "✅ Low risk. System stable."
    }
    notification.notify(
        title=f"Secure Sphere Scan: {scan_target}",
        message=phrases.get(impact, "Scan completed."),
        timeout=8,  # notification shows for 8 seconds
        app_name="Secure Sphere"
    )

db = SQLAlchemy(app)

# --- Models ---
class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.now)
    overall_risk = db.Column(db.String(20))

    findings = db.relationship("Finding", backref="scan", cascade="all,delete-orphan")

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"))
    category = db.Column(db.String(100))
    title = db.Column(db.String(255))
    description = db.Column(db.Text)
    likelihood = db.Column(db.Integer)
    impact = db.Column(db.Integer)
    risk_score = db.Column(db.Integer)
    severity = db.Column(db.String(20))

# --- Helpers ---
TOP_PORTS = [21,22,23,25,53,80,110,143,443,465,587,993,995,135,139,445,3306,3389,8080,8443]

def severity_from_score(score:int)->str:
    if score >= 16: return "Critical"
    if score >= 9: return "High"
    if score >= 4: return "Medium"
    return "Low"

def password_strength(pw:str):
    length = len(pw)
    sets = [
        bool(re.search(r"[a-z]", pw)),
        bool(re.search(r"[A-Z]", pw)),
        bool(re.search(r"\d", pw)),
        bool(re.search(r"[^A-Za-z0-9]", pw)),
    ]
    classes = sum(sets)
    if length < 8 or classes <= 2:
        likelihood = 4
        title = "Weak password policy"
        description = "Password appears weak (less than 8 chars or lacks character diversity). Use 12+ chars with upper/lower/digits/symbols; enable MFA."
    elif length < 12 or classes == 3:
        likelihood = 3
        title = "Moderate password policy"
        description = "Password is moderate. Increase length to 12-16 with full character mix; avoid reuse; enable MFA."
    else:
        likelihood = 2
        title = "Strong password"
        description = "Good password hygiene detected. Maintain rotation and MFA."
    impact = 4
    score = likelihood * impact
    return {
        "title": title,
        "description": description,
        "likelihood": likelihood,
        "impact": impact,
        "risk_score": score,
        "severity": severity_from_score(score)
    }

def scan_ports(host:str, ports:list[int]):
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            result = s.connect_ex((host, p))
            if result == 0:
                open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

def risk_for_port(port:int):
    common_high = {22,23,3389,445,3306}
    web = {80,443,8080,8443}
    email = {25,465,587,993,995,110,143}
    if port in common_high:
        likelihood = 4; impact = 4
        title = f"Exposed service on port {port}"; desc = f"Commonly targeted service (port {port}) is open. Harden config, restrict to trusted IPs, and enable auth."
    elif port in web:
        likelihood = 3; impact = 4
        title = f"Web service exposed on port {port}"; desc = f"Public web port {port} open. Ensure TLS, patching, and WAF/rate-limiting."
    elif port in email:
        likelihood = 3; impact = 3
        title = f"Mail-related service on port {port}"; desc = f"Mail/service port {port} open. Enforce TLS and authentication, monitor abuse."
    else:
        likelihood = 2; impact = 3
        title = f"Service on uncommon port {port}"; desc = f"Port {port} open. Verify necessity and restrict exposure."
    score = likelihood*impact
    return {"title": title, "description": desc, "likelihood": likelihood, "impact": impact, "risk_score": score, "severity": severity_from_score(score)}

def compute_overall_severity(findings:list[Finding])->str:
    order = ["Low","Medium","High","Critical"]
    max_s = "Low"
    for f in findings:
        if order.index(f.severity) > order.index(max_s):
            max_s = f.severity
    return max_s

# --- Routes ---
@app.route("/")
def index():
    scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template("index.html", scans=scans)

@app.route("/scan", methods=["GET","POST"])
def scan():
    if request.method == "POST":
        target = request.form.get("target","").strip()
        pw = request.form.get("password","").strip()
        speed = request.form.get("measured_speed","").strip()
        if not target:
            flash("Please enter a target (IP or hostname).","error")
            return redirect(url_for("scan"))
        try:
            socket.gethostbyname(target)
        except Exception:
            flash("Target cannot be resolved. Check IP/hostname.","error")
            return redirect(url_for("scan"))

        scan_obj = Scan(target=target)
        db.session.add(scan_obj)
        db.session.flush()

        opens = scan_ports(target, TOP_PORTS)
        findings = []

        for p in opens:
            port_risk = risk_for_port(p)
            f = Finding(scan_id=scan_obj.id, category="Open Port", title=port_risk["title"], description=port_risk["description"], likelihood=port_risk["likelihood"], impact=port_risk["impact"], risk_score=port_risk["risk_score"], severity=port_risk["severity"])
            findings.append(f); db.session.add(f)

        if pw:
            pr = password_strength(pw)
            f = Finding(scan_id=scan_obj.id, category="Password Policy", title=pr["title"], description=pr["description"], likelihood=pr["likelihood"], impact=pr["impact"], risk_score=pr["risk_score"], severity=pr["severity"])
            findings.append(f); db.session.add(f)

        db.session.flush()
        scan_obj.overall_risk = compute_overall_severity(findings) if findings else "Low"
        db.session.commit()
        send_system_alert(scan_obj.target, scan_obj.overall_risk)
        
        return redirect(url_for("results", scan_id=scan_obj.id))
        
    return render_template("scan.html")

@app.route("/results/<int:scan_id>")
def results(scan_id):
    scan_obj = Scan.query.get_or_404(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    counts = {"Low":0,"Medium":0,"High":0,"Critical":0}
    for f in findings:
        counts[f.severity] += 1
    heatmap = [[0]*5 for _ in range(5)]
    for f in findings:
        heatmap[f.likelihood-1][f.impact-1] += 1
    return render_template("results.html", scan=scan_obj, findings=findings, counts=counts, heatmap=heatmap)

@app.route("/report/<int:scan_id>.pdf")
def report_pdf(scan_id):
    scan_obj = Scan.query.get_or_404(scan_id)
    findings = Finding.query.filter_by(scan_id=scan_id).all()
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    def write_line(text, y):
        c.drawString(2*cm, y, text); return y - 14
    y = height - 2*cm
    c.setFont("Helvetica-Bold", 16); c.drawString(2*cm, y, "Secure Sphere – Risk Report"); y -= 20
    c.setFont("Helvetica", 11)
    y = write_line(f"Target: {scan_obj.target}", y)
    y = write_line(f"Date: {scan_obj.created_at.strftime('%Y-%m-%d %H:%M:%S')}", y)
    y = write_line(f"Overall Risk: {scan_obj.overall_risk}", y)
    y -= 10
    for f in findings:
        if y < 3*cm:
            c.showPage(); y = height - 2*cm; c.setFont("Helvetica", 11)
        c.setFont("Helvetica-Bold", 12); y = write_line(f"[{f.severity}] {f.category}: {f.title}", y)
        c.setFont("Helvetica", 10); y = write_line(f"Likelihood: {f.likelihood}  Impact: {f.impact}  Score: {f.risk_score}", y)
        desc = f.description; line = ""
        for word in desc.split():
            test = (line + " " + word).strip()
            if c.stringWidth(test, "Helvetica", 10) > width - 4*cm:
                y = write_line(line, y); line = word
            else:
                line = test
        if line:
            y = write_line(line, y)
        y -= 6
    c.showPage(); c.save(); buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"Secure Sphere_Report_{scan_id}.pdf", mimetype="application/pdf")

@app.route("/speedtest")
def speedtest():
    size = 500000
    from flask import request
    try:
        size = int(request.args.get("size", size))
        if size < 1000: size = 1000
        if size > 5_000_000: size = 5_000_000
    except Exception:
        size = 500000
    chunk = b"0" * 1024
    def generate():
        sent = 0
        while sent < size:
            tosend = min(1024, size - sent)
            sent += tosend
            yield chunk[:tosend]
    headers = {"Content-Type":"application/octet-stream","Content-Length":str(size),"Cache-Control":"no-cache, no-store, must-revalidate"}
    return Response(generate(), headers=headers)

@app.cli.command("init-db")
def init_db():
    db.create_all(); print("Database initialized.")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
