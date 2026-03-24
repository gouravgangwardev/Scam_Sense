#  Scam Sense AI

A web-based fraud prevention system that analyzes suspicious messages, links,
and screenshots using AI — and stops users before they become victims.

---

##  What It Does

| Feature | Description |
|---|---|
| Message Scan | Paste a suspicious SMS or WhatsApp message for analysis |
| Link Scan | Paste a suspicious URL to check for phishing patterns |
| Screenshot Scan | Upload a screenshot — text is extracted via OCR and analyzed |
| AI Detection | Classifies content as SAFE, SUSPICIOUS, or DANGEROUS |
| Fraud Prevention | Dangerous links are never opened — user is shown a red warning screen |
| Scam Reporting | Users can submit scams they received to improve the system |
| Statistics | Dashboard showing total scans and risk level breakdown |

---

## Project Structure

```
scam-sense-ai/
├── run.py                        # Start everything with one command
├── app.py                        # Flask app — all routes
├── config.py                     # All settings loaded from .env
├── requirements.txt              # Python dependencies
├── .env                          # Private keys (never share)
├── .gitignore                    # Protects private files from GitHub
│
├── utils/
│   ├── ai_client.py              # AI engine connection + fallback
│   ├── ocr_handler.py            # Image to text (Tesseract OCR)
│   ├── link_checker.py           # URL phishing pattern checker
│   ├── logger.py                 # Logs scans to database
│   ├── validators.py             # Input validation
│   └── file_cleanup.py           # Deletes uploads after scan
│
├── error_handlers/
│   └── handlers.py               # 400, 404, 413, 429, 500 error pages
│
├── middleware/
│   └── rate_limiter.py           # Limits 10 scans per minute per user
│
├── database/
│   ├── init_db.py                # Creates database tables
│   └── scans.db                  # SQLite database (auto-created)
│
├── uploads/                      # Temporary screenshot storage
│
└── templates/                    # HTML pages (frontend)
```

---

##  Requirements

- Python 3.10 or above
- Tesseract OCR installed on your system

### Install Tesseract OCR

**Windows:**
Download installer from https://github.com/tesseract-ocr/tesseract
and add it to your system PATH.

**Linux (Ubuntu/Debian):**
```bash
sudo apt install tesseract-ocr
```

**Mac:**
```bash
brew install tesseract
```

---

##  Setup and Run

### Step 1 — Clone or download the project
```bash
git clone https://github.com/yourusername/scam-sense-ai.git
cd scam-sense-ai
```

### Step 2 — Create and activate virtual environment
```bash
# Create
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on Mac / Linux
source venv/bin/activate
```

### Step 3 — Install all dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Set up your .env file
```bash
# Open .env and set your secret key
SECRET_KEY=your-long-random-secret-key-here
AI_ENGINE_URL=http://localhost:8000/analyze
DEBUG=True
PORT=5000
```

### Step 5 — Start the project
```bash
python run.py
```

`run.py` automatically:
- Creates `.env` if missing
- Creates `uploads/` folder if missing
- Initializes the database if not found
- Runs safety cleanup on old uploads
- Starts the Flask server

### Step 6 — Open in browser
```
http://localhost:5000
```

---

## 🔌 AI Engine

The system sends scan content to an external AI engine at `AI_ENGINE_URL`.

If the AI engine is **offline**, the system automatically switches to a
built-in **rule-based keyword detection** fallback. The app will never crash
if the AI server is unavailable.

Expected AI engine response format:
```json
{
    "risk_level": "DANGEROUS",
    "risk_score": 85,
    "explanation": "This message is impersonating a bank and requesting OTP."
}
```

---

## 📊 Risk Levels

| Level | Color | Meaning |
|---|---|---|
| SAFE | 🟢 Green | No scam indicators found |
| SUSPICIOUS | 🟠 Orange | Some suspicious patterns detected |
| DANGEROUS | 🔴 Red | High-confidence scam — link blocked |

---

## 🗄️ Database Tables

| Table | Purpose |
|---|---|
| `scans` | Logs every scan — type, risk level, timestamp |
| `reports` | Stores user-submitted scam reports |
| `blocked_links` | Saves every URL classified as DANGEROUS |

---

## 🚦 Rate Limits

| Route | Limit |
|---|---|
| Home page | 60 per minute |
| Scan routes | 10 per minute |
| Report form | 5 per minute |
| Stats page | 30 per minute |

---

## 🛡️ Security Features

- Input validation on all scan routes
- File type and size validation (JPG/PNG, max 5MB)
- Uploaded files deleted immediately after OCR
- Dangerous links never made clickable
- Rate limiting per IP address
- Session-based result storage
- Secret key loaded from environment variable

---

## 📦 Dependencies

| Library | Purpose |
|---|---|
| flask | Web framework |
| flask-limiter | Rate limiting |
| Pillow | Image processing |
| pytesseract | OCR text extraction |
| requests | HTTP calls to AI engine |
| python-dotenv | Load .env variables |
| gunicorn | Production WSGI server |

---

## 👥 Built For

- College project — handles up to 100 concurrent users
- Designed to protect students and senior citizens from digital fraud
- Pre-action intervention — stops fraud before financial loss occurs

---

## ⚠️ Important Notes

- Never share your `.env` file — it contains your secret key
- Always change `SECRET_KEY` before deploying to production
- Set `DEBUG=False` in production
- Use Gunicorn instead of Flask dev server for production:
```bash
gunicorn -w 4 app:app --bind 0.0.0.0:5000
```