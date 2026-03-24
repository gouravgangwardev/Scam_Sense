from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np
import re
import urllib.parse

app = Flask(__name__)
CORS(app)

# Load model, scaler, features
model = pickle.load(open('link_model.pkl', 'rb'))
scaler = pickle.load(open('link_scaler.pkl', 'rb'))
feature_names = pickle.load(open('link_features.pkl', 'rb'))

print("✅ Link AI model loaded")


def extract_features(url):
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        full = url.lower()

        suspicious_words = [
            "secure", "account", "update", "login",
            "verify", "bank", "otp", "password", "confirm"
        ]

        brand_names = [
            "paypal", "apple", "google", "amazon",
            "facebook", "microsoft", "netflix", "sbi",
            "hdfc", "icici", "paytm"
        ]

        features = {
            "NumDots": url.count('.'),
            "SubdomainLevel": len(hostname.split('.')) - 2 if hostname else 0,
            "PathLevel": len([p for p in path.split('/') if p]),
            "UrlLength": len(url),
            "NumDash": url.count('-'),
            "NumDashInHostname": hostname.count('-'),
            "AtSymbol": 1 if '@' in url else 0,
            "TildeSymbol": 1 if '~' in url else 0,
            "NumUnderscore": url.count('_'),
            "NumPercent": url.count('%'),
            "NumQueryComponents": len(query.split('&')) if query else 0,
            "NumAmpersand": url.count('&'),
            "NumHash": url.count('#'),
            "NumNumericChars": sum(c.isdigit() for c in url),
            "NoHttps": 0 if parsed.scheme == 'https' else 1,
            "RandomString": 1 if re.search(r'[a-z0-9]{15,}', hostname) else 0,
            "IpAddress": 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
            "DomainInSubdomains": 1 if any(b in hostname.split('.')[:-2] for b in brand_names) else 0,
            "DomainInPaths": 1 if any(b in path.lower() for b in brand_names) else 0,
            "HttpsInHostname": 1 if 'https' in hostname else 0,
            "HostnameLength": len(hostname),
            "PathLength": len(path),
            "QueryLength": len(query),
            "DoubleSlashInPath": 1 if '//' in path else 0,
            "NumSensitiveWords": sum(w in full for w in suspicious_words),
            "EmbeddedBrandName": 1 if any(b in full for b in brand_names) else 0,
            "PctExtHyperlinks": 0.0,
            "PctExtResourceUrls": 0.0,
            "ExtFavicon": 0,
            "InsecureForms": 0,
            "RelativeFormAction": 0,
            "ExtFormAction": 0,
            "AbnormalFormAction": 0,
            "PctNullSelfRedirectHyperlinks": 0.0,
            "FrequentDomainNameMismatch": 0,
            "FakeLinkInStatusBar": 0,
            "RightClickDisabled": 0,
            "PopUpWindow": 0,
            "SubmitInfoToEmail": 1 if 'mailto' in full else 0,
            "IframeOrFrame": 0,
            "MissingTitle": 0,
            "ImagesOnlyInForm": 0,
            "SubdomainLevelRT": 1 if len(hostname.split('.')) > 3 else 0,
            "UrlLengthRT": 1 if len(url) > 75 else -1,
            "PctExtResourceUrlsRT": 0,
            "AbnormalExtFormActionR": 0,
            "ExtMetaScriptLinkRT": 0,
            "PctExtNullSelfRedirectHyperlinksRT": 0,
        }

        # Build feature vector in correct order
        feature_vector = [features.get(f, 0) for f in feature_names]
        return feature_vector, features

    except Exception as e:
        return None, str(e)


# ─────────────────────────────────────────
# Risk Level Builder
# ─────────────────────────────────────────

def build_explanation(features, risk, score, lang='en'):
    explanation = []

    T = {
        "ip_detected": {
            "en": "URL uses a raw IP address instead of a domain name",
            "hi": "URL में डोमेन की जगह IP एड्रेस है",
            "es": "La URL usa una IP en lugar de un dominio"
        },
        "no_https": {
            "en": "Connection is not secure — no HTTPS",
            "hi": "कनेक्शन सुरक्षित नहीं है — HTTPS नहीं है",
            "es": "La conexión no es segura — sin HTTPS"
        },
        "brand_impersonation": {
            "en": "Known brand name found in suspicious position",
            "hi": "संदिग्ध स्थान पर जाना-पहचाना ब्रांड नाम मिला",
            "es": "Nombre de marca conocida en posición sospechosa"
        },
        "sensitive_words": {
            "en": "Sensitive keywords detected in URL",
            "hi": "URL में संवेदनशील शब्द मिले",
            "es": "Palabras sensibles detectadas en la URL"
        },
        "long_url": {
            "en": "URL is unusually long — common in phishing",
            "hi": "URL असामान्य रूप से लंबा है — फिशिंग में आम",
            "es": "URL inusualmente larga — común en phishing"
        },
        "at_symbol": {
            "en": "@ symbol in URL is a phishing indicator",
            "hi": "URL में @ चिह्न फिशिंग का संकेत है",
            "es": "El símbolo @ en la URL indica phishing"
        },
        "subdomain": {
            "en": "Multiple subdomains detected — suspicious structure",
            "hi": "एकाधिक सबडोमेन मिले — संदिग्ध संरचना",
            "es": "Múltiples subdominios — estructura sospechosa"
        },
        "random_string": {
            "en": "Random character string detected in hostname",
            "hi": "होस्टनेम में यादृच्छिक अक्षर मिले",
            "es": "Cadena de caracteres aleatoria en el hostname"
        },
        "safe": {
            "en": "No phishing indicators found in this URL",
            "hi": "इस URL में कोई फिशिंग संकेत नहीं मिला",
            "es": "No se encontraron indicadores de phishing"
        },
        "ai_phishing": {
            "en": "AI model identified this as a phishing URL",
            "hi": "एआई मॉडल ने इसे फिशिंग URL पाया",
            "es": "El modelo de IA identificó esto como phishing"
        },
        "ai_safe": {
            "en": "AI model identified this URL as legitimate",
            "hi": "एआई मॉडल ने इस URL को वैध पाया",
            "es": "El modelo de IA identificó esta URL como legítima"
        }
    }

    if isinstance(features, dict):
        if features.get("IpAddress"):
            explanation.append("🚨 " + T["ip_detected"][lang])
        if features.get("NoHttps"):
            explanation.append("🔓 " + T["no_https"][lang])
        if features.get("EmbeddedBrandName") or features.get("DomainInSubdomains"):
            explanation.append("🎭 " + T["brand_impersonation"][lang])
        if features.get("NumSensitiveWords", 0) > 0:
            explanation.append("⚠️ " + T["sensitive_words"][lang])
        if features.get("UrlLength", 0) > 75:
            explanation.append("📏 " + T["long_url"][lang])
        if features.get("AtSymbol"):
            explanation.append("🚩 " + T["at_symbol"][lang])
        if features.get("SubdomainLevel", 0) > 2:
            explanation.append("🌐 " + T["subdomain"][lang])
        if features.get("RandomString"):
            explanation.append("🔤 " + T["random_string"][lang])

    if risk == "DANGEROUS":
        explanation.append("🤖 " + T["ai_phishing"][lang])
    elif risk == "SAFE":
        explanation.append("✅ " + T["ai_safe"][lang])
        if not explanation[:-1]:
            explanation.insert(0, T["safe"][lang])

    return explanation


# ─────────────────────────────────────────
# Routes
# ─────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "link_ai running", "port": 5002})


@app.route('/predict/url', methods=['POST'])
def predict_url():
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({"error": "No URL provided"}), 400

    url = data['url'].strip()
    lang = data.get('lang', 'en')

    if lang not in ['en', 'hi', 'es']:
        lang = 'en'

    # Basic validation
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # Extract features
    feature_vector, features = extract_features(url)

    if feature_vector is None:
        return jsonify({"error": f"Could not parse URL: {features}"}), 400

    # AI prediction
    scaled = scaler.transform([feature_vector])
    prediction = model.predict(scaled)[0]
    proba = model.predict_proba(scaled)[0][1]
    score = round(float(proba), 2)

    # Determine risk level
    if prediction == 1:
        if score >= 0.80:
            risk = "DANGEROUS"
        else:
            risk = "SUSPICIOUS"
    else:
        if score >= 0.40:
            risk = "SUSPICIOUS"
        else:
            risk = "SAFE"

    # Build explanation
    explanation = build_explanation(features, risk, score, lang)

    return jsonify({
        "risk": risk,
        "score": score,
        "explanation": explanation,
        "url": url
    })


if __name__ == '__main__':
    app.run(debug=True, port=5002)
