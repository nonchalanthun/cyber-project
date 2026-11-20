import logging
from flask import Flask, render_template, request, jsonify
from password_checker.analyzer import analyze_password
from password_checker.generator import generate_random_password, generate_passphrase

app = Flask(__name__)

# Suppress default verbose logging to minimize any accidental metadata exposure
log = logging.getLogger("werkzeug")
log.setLevel(logging.ERROR)


@app.after_request
def apply_security_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


# --- Page Routes ---
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyzer")
def analyzer_page():
    return render_template("analyzer.html")


@app.route("/generator")
def generator_page():
    return render_template("generator.html")


@app.route("/report")
def report_page():
    return render_template("report.html")


@app.route("/about")
def about_page():
    return render_template("about.html")


# --- API Routes ---
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    check_breach = bool(data.get("check_breach", False))

    if not password:
        return jsonify({"error": "Please enter a password."}), 400

    result = analyze_password(password, check_breach=check_breach)
    # Explicitly clear local reference
    del password
    return jsonify(result), 200


@app.route("/api/generate", methods=["POST"])
def api_generate():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "random")

    if mode == "passphrase":
        num_words = int(data.get("num_words", 5))
        separator = str(data.get("separator", "-"))[:3]
        capitalize = bool(data.get("capitalize", True))
        generated = generate_passphrase(num_words, separator, capitalize)
    else:
        length = int(data.get("length", 16))
        generated = generate_random_password(
            length=length,
            use_upper=bool(data.get("use_upper", True)),
            use_lower=bool(data.get("use_lower", True)),
            use_digits=bool(data.get("use_digits", True)),
            use_symbols=bool(data.get("use_symbols", True)),
        )

    return jsonify({"password": generated}), 200


if __name__ == "__main__":
    # Never run debug=True in production (prevents Werkzeug debugger from exposing variables)
 app.run(host="127.0.0.1", port=5001, debug=False)