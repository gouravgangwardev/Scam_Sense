from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import re

app = Flask(__name__)
CORS(app)

# Load model
model = pickle.load(open('spam_model.pkl', 'rb'))
vectorizer = pickle.load(open('vectorizer.pkl', 'rb'))

# Clean text
def clean_text(text):
    text = text.lower()
    text = re.sub(r'[^a-zA-Z]', ' ', text)
    return text

# UI Translations
uiText = {
    "en": {
        "title": "🛡 ScamSense AI",
        "guardian": "Guardian Mode",
        "placeholder": "Paste suspicious message here...",
        "button": "Analyze",
        "safe": "🟢 Safe Message",
        "suspicious": "🟡 Suspicious Message",
        "dangerous": "🔴 Dangerous Message",
        "why": "Why:"
    },
    "hi": {
        "title": "🛡 स्कैमसेंस एआई",
        "guardian": "गार्डियन मोड",
        "placeholder": "यहाँ संदिग्ध संदेश पेस्ट करें...",
        "button": "विश्लेषण करें",
        "safe": "🟢 सुरक्षित संदेश",
        "suspicious": "🟡 संदिग्ध संदेश",
        "dangerous": "🔴 खतरनाक संदेश",
        "why": "क्यों:"
    },
    "es": {
        "title": "🛡 ScamSense AI",
        "guardian": "Modo Guardián",
        "placeholder": "Pega el mensaje aquí...",
        "button": "Analizar",
        "safe": "🟢 Mensaje seguro",
        "suspicious": "🟡 Mensaje sospechoso",
        "dangerous": "🔴 Mensaje peligroso",
        "why": "Por qué:"
    }
}

# Detection translations
T = {
    "suspicious": {
        "en": "Suspicious word detected",
        "hi": "संदिग्ध शब्द मिला",
        "es": "Palabra sospechosa detectada"
    },
    "danger": {
        "en": "Sensitive data request detected",
        "hi": "संवेदनशील जानकारी मांगी गई",
        "es": "Solicitud de datos sensibles detectada"
    },
    "urgency": {
        "en": "Urgency detected",
        "hi": "तत्कालता पाई गई",
        "es": "Urgencia detectada"
    },
    "ai_spam": {
        "en": "AI detected spam pattern",
        "hi": "एआई ने स्पैम पैटर्न पाया",
        "es": "La IA detectó patrón de spam"
    },
    "ai_safe": {
        "en": "AI detected safe message",
        "hi": "एआई ने इसे सुरक्षित पाया",
        "es": "La IA lo encontró seguro"
    },
    "safe": {
        "en": "No suspicious content found",
        "hi": "कोई संदिग्ध सामग्री नहीं मिली",
        "es": "No se encontró contenido sospechoso"
    },
    "guardian_on": {
        "en": "Guardian Mode: High security enabled",
        "hi": "गार्डियन मोड: उच्च सुरक्षा सक्रिय",
        "es": "Modo Guardián: alta seguridad activada"
    },
    "no_otp": {
        "en": "Never share OTP or password",
        "hi": "कभी भी OTP या पासवर्ड साझा न करें",
        "es": "Nunca compartas OTP o contraseña"
    },
    "no_click": {
        "en": "Avoid clicking unknown links",
        "hi": "अज्ञात लिंक पर क्लिक न करें",
        "es": "Evita hacer clic en enlaces desconocidos"
    },
    "verify": {
        "en": "Always verify sender before action",
        "hi": "कार्रवाई से पहले प्रेषक की पुष्टि करें",
        "es": "Verifica siempre el remitente"
    },
    "guardian_safe_note": {
        "en": "Guardian Mode: Even safe messages should be verified",
        "hi": "गार्डियन मोड: सुरक्षित संदेश भी सत्यापित करें",
        "es": "Modo Guardián: verifica incluso mensajes seguros"
    }
}

@app.route('/get_ui_text', methods=['GET'])
def get_ui_text():
    return jsonify(uiText)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "message_ai running", "port": 5001})

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()

    if not data or 'email' not in data:
        return jsonify({"error": "No message provided"}), 400

    raw_text = data['email']
    email = clean_text(raw_text)
    guardian = data.get('guardian', False)
    lang = data.get('lang', 'en')

    # Validate language
    if lang not in T['suspicious']:
        lang = 'en'

    risk = "SAFE"
    explanation = []

    # Keywords
    spam_keywords = ["lottery", "win", "won", "prize", "click", "urgent"]
    danger_keywords = ["otp", "bank", "password", "verify", "account"]
    urgency_words = ["urgent", "immediately", "now", "asap"]

    # Keyword detection
    for word in spam_keywords:
        if word in email:
            risk = "SUSPICIOUS"
            explanation.append(f"{T['suspicious'][lang]}: '{word}'")

    for word in danger_keywords:
        if word in email:
            risk = "DANGEROUS"
            explanation.append(f"{T['danger'][lang]}: '{word}'")

    for word in urgency_words:
        if word in email:
            explanation.append(f"{T['urgency'][lang]}: '{word}'")
            if risk == "SAFE":
                risk = "SUSPICIOUS"

    # AI model prediction
    transformed = vectorizer.transform([email])
    result = model.predict(transformed)[0]

    # Confidence score
    proba = model.predict_proba(transformed)[0][1]
    score = round(float(proba), 2)

    if result == 1:
        explanation.append(T["ai_spam"][lang])
        if risk == "SAFE":
            risk = "SUSPICIOUS"
    else:
        explanation.append(T["ai_safe"][lang])

    if risk == "SAFE":
        explanation.append(T["safe"][lang])

    # Guardian Mode
    if guardian:
        if risk == "SAFE":
            explanation.append("⚠️ " + T["guardian_safe_note"][lang])
        else:
            risk = "DANGEROUS"

        explanation.append("⚠️ " + T["guardian_on"][lang])

        if "otp" in email or "password" in email:
            explanation.append("🚫 " + T["no_otp"][lang])

        if "click" in email or "link" in email:
            explanation.append("🚫 " + T["no_click"][lang])

        explanation.append("🔐 " + T["verify"][lang])

    return jsonify({
        "risk": risk,
        "score": score,
        "explanation": explanation
    })

if __name__ == '__main__':
    app.run(debug=True, port=5001)