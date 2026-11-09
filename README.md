# CyberLegal Assistant

CyberLegal Assistant is a local academic project for preliminary cyber-incident intake. It keeps the existing Flask-rendered frontend and uses Google's official GenAI Python SDK to summarize incidents, ask a relevant follow-up question when needed, and suggest evidence-preservation and safety steps.

This tool does not establish that a crime occurred, file a police report, or provide formal legal advice. The checked-in legal guidance dataset contains general educational guidance, not a verified section-by-section statutory mapping, so the application does not generate legal section citations.

## Requirements

- Python 3.10 or later
- A Gemini API key and API access for live analysis

The default local database is SQLite. The existing optional MySQL configuration remains available through environment variables.

## Setup on Windows

From the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and set:

```dotenv
GEMINI_API_KEY=your_server_side_api_key
GEMINI_MODEL=gemini-3.1-flash-lite
SECRET_KEY=replace_with_a_long_random_secret
FLASK_DEBUG=false
```

Keep `.env` private; it is excluded from Git. Never put the Gemini key in frontend JavaScript. `GEMINI_MODEL` defaults to `gemini-3.1-flash-lite`; set it to a model available to your Gemini API account if needed. Gemini 3 requests use the supported minimal thinking level and structured JSON output; the server validates the required assessment fields before saving a result. Sanitized backend diagnostics include the model, provider status/code, and parse or safety failure category without logging complaint or response contents. Rate limits and model availability are project-specific; the app reports quota exhaustion without fabricating an assessment and only retries a 429 once when Google supplies a short retry delay. The app reports unsupported model configuration clearly rather than switching to an unconfigured model. The installed Google GenAI SDK is supported across versions 1.75.x and 2.x. Users can create an account through the existing registration page. Optional `APP_USERNAME` and `APP_PASSWORD` values enable an additional local administrator login; do not use a default or shared password.

To use MySQL instead of SQLite, configure `DB_TYPE`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD` in `.env`. The database schema is initialized at startup; existing report data is preserved.

## Run

```powershell
.\.venv\Scripts\Activate.ps1
python app.py
```

Open <http://127.0.0.1:5000>. Without `GEMINI_API_KEY`, the site and health endpoint remain available, but analysis returns a configuration error instead of claiming an assessment succeeded.

To make one real, harmless Gemini diagnostic request using the same model and structured response configuration as the chatbot, run:

```powershell
python .\scripts\diagnose_gemini.py
```

The diagnostic prints the SDK version, configured model, HTTP status/category, and a safe explanation only. It never prints the key or complaint content. Each invocation makes at most one provider request; it can consume API quota.

## API

- `GET /api/health` — application health, whether the server has an API key configured, and the effective model/SDK version (never returns the key).
- `POST /api/chat` — authenticated incident analysis. JSON: `{"message":"...","session_id":"optional-session-id"}`.
- `POST /api/chat/retry` — authenticated retry of the most recent saved message in a conversation whose analysis failed. JSON: `{"session_id":"..."}`. A retry does not insert another complaint or chat message.
- `GET /api/chat-history?q=<query>` and `GET /api/chat-history/<session_id>` — authenticated, owner-scoped conversation history; search matches complaint text, category, saved keywords, title, and associated report IDs.
- `POST /api/reports`, `GET /api/reports`, `GET /api/reports/<report_id>` — authenticated report operations scoped to the signed-in account.

Successful `/api/chat` analyses include the likely crime type, an explicitly estimated confidence, severity and its explanation, summary, indicators, missing information, evidence to preserve, recommended actions, and a preliminary-assessment disclaimer. Legal guidance identifies possible review topics only; it does not invent statutory citations and explicitly says when legal verification is needed. Existing response fields such as `category`, `urgency`, `evidence`, and `next_steps` remain available for compatibility.

The chatbot retains recent turns in the existing SQLite/MySQL database so short responses such as “Yes” can be understood in context. A new assessment receives a fresh conversation ID; opening a history item explicitly restores that conversation. Existing databases are upgraded at startup with conversation title, keyword, and last-updated metadata while preserving saved reports and chat messages. The Chat History page supports partial, case-insensitive searches across complaint text, assessed category, stored keywords, title, and associated report ID. If Gemini is temporarily unavailable, the complaint remains saved with an unavailable status; use the in-chat **Retry analysis** action to retry the most recent message without duplicating it. Transient provider failures receive a small bounded retry with backoff; authentication, model configuration, and billing errors are not retried automatically. Use **New Assessment** or **New complaint** to start a separate conversation. Inputs are size-limited, rate-limited, and rejected if they appear to contain an actual OTP, PIN, CVV, or password value. Do not enter authentication secrets.

## Tests

Run the automated tests with mocked provider responses (no API key or paid request required):

```powershell
py -m unittest discover -s tests -v
```

To manually test real analysis, configure the key in `.env`, start the app, sign in, and submit a test incident in the chatbot. Live generation requests may incur API usage charges.
