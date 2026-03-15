from flask import Flask, render_template, request, jsonify
import joblib
import pytesseract
from PIL import Image
import os

app = Flask(__name__)

# EMAIL MODEL LOAD
email_model = joblib.load("models/email_model.pkl")
email_vectorizer = joblib.load("models/email_vectorizer.pkl")


@app.route("/")
def login():
    return render_template("login.html")


@app.route("/signup")
def signup():
    return render_template("signup.html")


@app.route("/home")
def home():
    return render_template("home.html")


# ================= EMAIL DETECTION =================
@app.route("/check_email", methods=["POST"])
def check_email():

    text = request.form["email_text"]

    vector = email_vectorizer.transform([text])
    prediction = email_model.predict(vector)[0]

    if prediction == 1:

        result = "⚠ Scam Email Detected"
        risk = 80
        color = "red"

        reasons = [
            "Suspicious keywords detected",
            "Email similar to phishing patterns",
            "Possible scam behaviour"
        ]

    else:

        result = "✅ Likely Safe"
        risk = 15
        color = "green"

        reasons = [
            "No scam keywords found",
            "Email structure looks normal",
            "No phishing indicators"
        ]

    return render_template("home.html",
                           result=result,
                           score=str(risk) + "%",
                           color=color,
                           reasons=reasons)


# ================= POSTER / ADS DETECTION =================
@app.route("/check_poster", methods=["POST"])
def check_poster():

    file = request.files["poster"]

    path = os.path.join("static", file.filename)
    file.save(path)

    text = pytesseract.image_to_string(Image.open(path))
    text = text.lower()

    scam_words = ["free", "offer", "click", "limited", "urgent"]

    risk = 20
    color = "green"
    result = "✅ Likely Safe"
    reasons = ["Advertisement text looks normal"]

    for word in scam_words:

        if word in text:

            risk = 75
            color = "red"
            result = "⚠ Suspicious Advertisement"

            reasons = [
                "Marketing scam keywords detected",
                "Common scam advertisement pattern"
            ]

            break

    return render_template("home.html",
                           result=result,
                           score=str(risk) + "%",
                           color=color,
                           reasons=reasons)


# ================= INSTAGRAM DETECTION =================
@app.route("/check_instagram", methods=["POST"])
def check_instagram():

    insta = request.form["insta_id"]

    risk = 20
    color = "green"
    result = "✅ Likely Safe"
    reasons = []

    if len(insta) < 5:

        risk = 60
        color = "red"
        result = "⚠ Suspicious Instagram ID"
        reasons.append("Username too short")

    if "shop" in insta.lower() or "sale" in insta.lower():

        risk = 50
        color = "red"
        result = "⚠ Suspicious Seller Account"
        reasons.append("Selling keyword detected")

    if insta.isnumeric():

        risk = 85
        color = "red"
        result = "⚠ High Scam Risk"
        reasons.append("Numeric username pattern")

    if not reasons:
        reasons.append("Username pattern looks normal")

    return render_template("home.html",
                           result=result,
                           score=str(risk) + "%",
                           color=color,
                           reasons=reasons)


# ================= WEBSITE PHISHING DETECTION =================
@app.route("/check_website", methods=["POST"])
def check_website():

    url = request.form["website_url"]

    risk = 20
    color = "green"
    result = "✅ Likely Safe"
    reasons = []

    # Suspicious keywords
    if "login" in url.lower() or "verify" in url.lower() or "secure" in url.lower():

        risk = 60
        color = "red"
        result = "⚠ Suspicious Website"
        reasons.append("Suspicious keywords found in URL")

    # HTTPS check
    if not url.startswith("https://"):

        risk += 20
        color = "red"
        reasons.append("Website does not use HTTPS")

    # IP address check
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]

    if domain.replace(".", "").isdigit():

        risk = 85
        color = "red"
        result = "⚠ High Phishing Risk"
        reasons.append("Website uses IP address instead of domain")

    if not reasons:
        reasons.append("Website structure looks normal")

    return render_template("home.html",
                           result=result,
                           score=str(risk) + "%",
                           color=color,
                           reasons=reasons)


# ================= CHATBOT =================
@app.route("/chatbot", methods=["POST"])
def chatbot():

    msg = request.form["message"].lower()

    if "scam" in msg:
        reply = "Scams usually ask for OTP, advance payment or personal data."

    elif "instagram" in msg:
        reply = "Always check followers, reviews and avoid advance payment."

    elif "email" in msg:
        reply = "Avoid emails asking for urgent payment or login credentials."

    elif "website" in msg:
        reply = "Always check HTTPS and domain name before entering personal information."

    else:
        reply = "I can help detect scams in Emails, Ads, Websites and Instagram sellers."

    return jsonify({"reply": reply})


if __name__ == "__main__":
    app.run(debug=True)