import json
import logging
import os
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
from typing import Any, Dict, List, Optional, Tuple

import mysql.connector
from dotenv import load_dotenv
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, make_response
from werkzeug.security import check_password_hash, generate_password_hash
from services.gemini_service import (
    AnalysisConfigurationError,
    AnalysisServiceError,
    analyze_complaint,
    get_configured_model,
)

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config["DATABASE"] = os.getenv("CYBERLEGAL_DB_PATH") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "cyberlegal.db")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
APP_USERNAME = os.getenv("APP_USERNAME", "")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "legal_data.json")
DB_SCHEMA_PATH = os.path.join(BASE_DIR, "database", "schema.sql")
SESSION_STORE: Dict[str, Dict[str, Any]] = {}
CHAT_REQUEST_TIMES: Dict[str, List[float]] = {}
logger = logging.getLogger(__name__)

LANGUAGE_MAP = {
    "en": "English",
    "ta": "Tamil",
    "hi": "Hindi",
    "auto": "Auto Detect",
}

TAMIL_TO_ENGLISH = {
    "என்": "my",
    "என்னுடைய": "my",
    "அனுமதி": "permission",
    "இல்லாமல்": "without",
    "பணம்": "money",
    "கணக்கு": "account",
    "வங்கி": "bank",
    "போலி": "fake",
    "மோசடி": "fraud",
    "இன்ஸ்டாகிராம்": "instagram",
    "அகாட்": "account",
    "இணைப்பு": "link",
    "கடவுச்சொல்": "password",
    "பயன்": "use",
    "நேரம்": "time",
    "மதிப்பு": "value",
    "கேள்வி": "question",
    "உங்கள்": "your",
    "நீங்கள்": "you",
    "அவர்கள்": "they",
    "பிற": "other",
    "போதும்": "enough",
    "அழைப்பு": "call",
    "சேதம்": "damage",
    "சொந்த": "own",
    "உரிமை": "rights",
    "கையாள": "handle",
    "பயோ": "photo",
    "கணக்கை": "account",
    "நம்பிய": "trusted",
    "சம்பந்தப்பட்ட": "related"
}

HINDI_TO_ENGLISH = {
    "बैंक": "bank",
    "खाता": "account",
    "पैसे": "money",
    "बिना": "without",
    "अनुमति": "permission",
    "धोखाधड़ी": "fraud",
    "नकली": "fake",
    "अकाउंट": "account",
    "इंस्टाग्राम": "instagram",
    "लिंक": "link",
    "पासवर्ड": "password",
    "संदिग्ध": "suspicious",
    "जानकारी": "information",
    "ट्रांसफर": "transfer",
    "हैक": "hack",
    "उपयोग": "use",
    "मुझे": "me",
    "मेरा": "my",
    "किसी": "someone",
    "बनाया": "created",
    "अभिभावक": "profile",
    "फर्जी": "fake",
    "संदेश": "message"
}

ROMAN_TAMIL = {
    "en": "my",
    "enakku": "me",
    "pannirukanga": "created",
    "fake": "fake",
    "account": "account",
    "money": "money",
    "transfer": "transfer",
    "permission": "permission",
    "illama": "without",
    "bank": "bank",
    "instagram": "instagram",
    "photo": "photo",
    "link": "link",
    "password": "password",
    "details": "details",
    "hack": "hack",
    "suspicious": "suspicious",
    "messages": "messages",
    "profile": "profile",
    "fake account": "fake account"
}

ROMAN_TAMIL.update({
    "aagum": "will be",
    "nu": "that",
    "oru": "a",
    "message vandhuchu": "message came",
    "andha": "that",
    "click pannadhukku apram": "after clicking",
    "irundhu": "from",
    "aayiduchu": "happened",
    "block": "blocked",
    "account la": "account",
    "link ah": "link",
})

ROMAN_HINDI = {
    "mere": "my",
    "bina": "without",
    "permission": "permission",
    "paise": "money",
    "account": "account",
    "transfer": "transfer",
    "fake": "fake",
    "instagram": "instagram",
    "link": "link",
    "password": "password",
    "details": "details",
    "hack": "hack",
    "suspicious": "suspicious",
    "message": "message",
    "a/c": "account"
}

with open(DATA_PATH, "r", encoding="utf-8") as file:
    LEGAL_DATA = json.load(file)
LEGAL_GUIDANCE_MAP = {
    item["category"]: item for item in LEGAL_DATA.get("categories", [])
}

CATEGORY_PATTERNS: Dict[str, Dict[str, List[str]]] = {
    "Financial Cyber Fraud": {
        "strong": [
            "unauthorized transaction",
            "money disappeared",
            "money was taken",
            "fraudulent transfer",
            "transferred money",
            "bank account",
            "unauthorized payment",
            "lost money",
            "fake banking call",
            "upi fraud",
            "upi payment",
            "payment was made",
            "someone tricked me",
            "stolen money",
            "wallet was drained",
            "money was stolen",
            "bank account hacked",
            "fraudulent payment request",
            "digital payment scam",
            "payment fraud"
        ],
        "medium": [
            "transaction",
            "payment",
            "bank",
            "account",
            "money",
            "banking",
            "wallet",
            "cash",
            "upi",
            "debit",
            "withdrawal",
            "transfer"
        ],
        "weak": [
            "fraud",
            "scam",
            "debit",
            "withdrawal",
            "payment request"
        ]
    },
    "Phishing": {
        "strong": [
            "fake login page",
            "suspicious link",
            "clicked a suspicious link",
            "account suspended",
            "verify my account",
            "banking link",
            "reset password",
            "fake email",
            "suspicious email",
            "account would be suspended",
            "clicked a verification link",
            "otp entered on fake site",
            "fake bank website",
            "banking alert link",
            "security alert asking for otp",
            "fake login portal"
        ],
        "medium": [
            "email",
            "link",
            "login",
            "password",
            "otp",
            "verification",
            "portal",
            "bank message"
        ],
        "weak": [
            "phish",
            "fake page",
            "security alert",
            "verification request"
        ]
    },
    "Identity Theft": {
        "strong": [
            "using my identity",
            "using my personal information",
            "using my name",
            "fake account using my name",
            "identity theft",
            "someone is using my identity",
            "using my profile",
            "misusing my aadhaar",
            "using my documents",
            "someone opened account in my name",
            "using my pan",
            "using my photo without consent"
        ],
        "medium": [
            "identity",
            "personal information",
            "account created",
            "fake account",
            "details",
            "document",
            "aadhaar",
            "pan"
        ],
        "weak": [
            "impersonation",
            "profile",
            "identity fraud"
        ]
    },
    "Social Media Crime": {
        "strong": [
            "instagram account",
            "facebook account",
            "twitter account",
            "fake instagram account",
            "pretending to be me",
            "using my name on social media",
            "fake profile",
            "impersonating me",
            "created an account using my name",
            "fake profile on instagram",
            "someone made a fake facebook page in my name",
            "impersonating me on whatsapp",
            "account pretending to be me"
        ],
        "medium": [
            "instagram",
            "facebook",
            "social media",
            "profile",
            "handle",
            "username",
            "whatsapp",
            "x account",
            "telegram"
        ],
        "weak": [
            "online impersonation",
            "fake account",
            "pretending",
            "profile clone"
        ]
    },
    "Unauthorized Account Access": {
        "strong": [
            "logged into my account without permission",
            "someone logged into my account",
            "unauthorized login",
            "my password stopped working",
            "account was hacked",
            "accessed my account",
            "login without my permission",
            "hacked my email",
            "hacked my account",
            "someone hacked my social media account",
            "unauthorized access to my account",
            "my device was hacked",
            "my login was compromised",
            "someone logged in from another device"
        ],
        "medium": [
            "account access",
            "logged in",
            "password",
            "login",
            "security alert",
            "device compromise",
            "unauthorized access",
            "accessed"
        ],
        "weak": [
            "hacked",
            "compromised",
            "access",
            "account takeover"
        ]
    },
    "Online Harassment": {
        "strong": [
            "abusive messages",
            "threatening messages",
            "repeatedly sends me abusive messages",
            "harassing me online",
            "threatening me online",
            "bullying me",
            "hate messages",
            "harassment",
            "abusive whatsapp messages",
            "sending abusive texts",
            "online bullying",
            "repeated vulgar messages"
        ],
        "medium": [
            "messages",
            "threats",
            "abuse",
            "harassment",
            "online",
            "whatsapp",
            "sms",
            "chat"
        ],
        "weak": [
            "bully",
            "abusive",
            "threat",
            "intimidation"
        ]
    },
    "Data Theft / Data Exposure": {
        "strong": [
            "personal information leaked",
            "data exposed",
            "customer data was exposed",
            "my data was leaked",
            "personal data leaked",
            "data theft",
            "data breach",
            "my documents were leaked",
            "my photos were leaked",
            "private data was exposed",
            "my information was published",
            "confidential files were stolen",
            "data leak"
        ],
        "medium": [
            "data",
            "leaked",
            "exposed",
            "information",
            "records",
            "documents",
            "photos",
            "private files"
        ],
        "weak": [
            "privacy",
            "breach",
            "records",
            "leak"
        ]
    },
    "Cyberstalking": {
        "strong": [
            "stalking me online",
            "cyberstalking",
            "following me online",
            "tracking my location",
            "monitoring my activity",
            "repeatedly following me",
            "tracking my phone",
            "following my every move online",
            "watching my profile continuously",
            "someone keeps monitoring my profile"
        ],
        "medium": [
            "stalking",
            "follow me",
            "location",
            "tracking",
            "online monitoring",
            "watching",
            "following"
        ],
        "weak": [
            "monitoring",
            "tracking me",
            "stalking"
        ]
    },
    "Online Impersonation": {
        "strong": [
            "pretending to be me",
            "fake profile pretending to be me",
            "impersonating me online",
            "pretending to be someone else",
            "using my photo",
            "fake social media account",
            "someone used my photo to create account",
            "using my name on a fake account",
            "clone account using my identity"
        ],
        "medium": [
            "impersonation",
            "fake profile",
            "pretending",
            "social media account",
            "profile picture",
            "photo used",
            "clone account"
        ],
        "weak": [
            "fake account",
            "someone else",
            "profile clone"
        ]
    },
    "Malware / Malicious Software": {
        "strong": [
            "malware",
            "virus",
            "trojan",
            "spyware",
            "ransomware",
            "downloaded a malicious file",
            "malicious software",
            "malicious link",
            "mobile phone infected with virus",
            "my pc got a trojan",
            "someone sent me malware",
            "downloaded a virus"
        ],
        "medium": [
            "virus",
            "download",
            "file",
            "trojan",
            "infected",
            "spyware",
            "malicious"
        ],
        "weak": [
            "malicious",
            "suspicious file",
            "dangerous link",
            "infected device"
        ]
    },
    "UPI Fraud": {
        "strong": [
            "upi fraud",
            "upi transaction",
            "fake upi request",
            "phonepe fraud",
            "gpay fraud",
            "paytm scam",
            "upi payment was made",
            "qr code scam",
            "fake payment link",
            "someone tricked me into paying"
        ],
        "medium": [
            "upi",
            "gpay",
            "phonepe",
            "paytm",
            "payment app",
            "qr code",
            "payment request"
        ],
        "weak": [
            "payment fraud",
            "paytm",
            "qr code",
            "payment request"
        ]
    },
    "OTP / Credential Fraud": {
        "strong": [
            "otp fraud",
            "otp stolen",
            "password stolen",
            "credentials were stolen",
            "someone used my otp",
            "one time password",
            "credential theft",
            "otp was shared",
            "password was shared",
            "my credentials were leaked",
            "security code stolen"
        ],
        "medium": [
            "otp",
            "password",
            "credentials",
            "security code",
            "login code",
            "password reset"
        ],
        "weak": [
            "compromised",
            "stolen",
            "credential misuse"
        ]
    },
    "Cyber Extortion": {
        "strong": [
            "blackmail",
            "extortion",
            "threat to leak data",
            "pay me or i will leak",
            "demanding money",
            "extort me",
            "blackmailing me",
            "someone is threatening to share my photos",
            "pay or i will expose you",
            "demanding ransomware payment",
            "threatening to leak my private data"
        ],
        "medium": [
            "threat",
            "demand",
            "money",
            "pay",
            "leak",
            "blackmail",
            "ransom"
        ],
        "weak": [
            "coercion",
            "intimidation",
            "threatening"
        ]
    },
    "Fake Website / Online Scam": {
        "strong": [
            "fake website",
            "fake app",
            "clone website",
            "scam website",
            "online scam",
            "fraudulent website",
            "fake banking site",
            "fake ecommerce site",
            "clone of bank website",
            "fraudulent app",
            "scam portal"
        ],
        "medium": [
            "website",
            "app",
            "portal",
            "login page",
            "checkout page",
            "clone",
            "ecommerce"
        ],
        "weak": [
            "scam",
            "fraud",
            "clone",
            "fake link"
        ]
    }
}

QUESTION_BANK: Dict[str, List[Dict[str, Any]]] = {
    "Social Media Crime": [
        {"question": "Is the account actively pretending to be you?", "options": ["Yes", "No", "Not sure"]},
        {"question": "Do you have a screenshot or profile URL for the fake account?", "options": ["Yes", "No", "Not sure"]}
    ],
    "Identity Theft": [
        {"question": "Is someone using your personal details or documents to create accounts or impersonate you?", "options": ["Yes", "No", "Not sure"]},
        {"question": "Have you already notified the platform or service provider about the misuse?", "options": ["Yes", "No", "Not sure"]}
    ],
    "Financial Cyber Fraud": [
        {"question": "Did the money leave your bank account without your authorization?", "options": ["Yes", "No", "Not sure"]},
        {"question": "Did you receive a call, SMS, or message that requested payment or verification?", "options": ["Yes", "No", "Not sure"]}
    ],
    "Phishing": [
        {"question": "Did you click a link or reply to a suspicious message?", "options": ["Yes", "No", "Not sure"]},
        {"question": "Did the message ask you to enter your password, OTP, or banking details?", "options": ["Yes", "No", "Not sure"]}
    ],
    "Online Harassment": [
        {"question": "Are the messages repeated, abusive, or threatening?", "options": ["Yes", "No", "Not sure"]},
        {"question": "Have you saved screenshots or blocked the sender?", "options": ["Yes", "No", "Not sure"]}
    ],
    "Unauthorized Account Access": [
        {"question": "Did you notice suspicious activity or a login from an unknown device?", "options": ["Yes", "No", "Not sure"]},
        {"question": "Have you already changed your login credentials?", "options": ["Yes", "No", "Not sure"]}
    ],
    "default": [
        {"question": "Do you have screenshots, messages, or documents related to the incident?", "options": ["Yes", "No", "Not sure"]},
        {"question": "Has the incident caused financial loss, account access issues, or reputational harm?", "options": ["Yes", "No", "Not sure"]}
    ]
}

RELATED_CATEGORY_MAP = {
    "Social Media Crime": "Identity Theft / Impersonation",
    "Online Impersonation": "Identity Theft / Impersonation",
    "Identity Theft": "Identity Theft / Impersonation",
    "Financial Cyber Fraud": "Financial Cyber Fraud",
    "UPI Fraud": "Financial Cyber Fraud",
    "OTP / Credential Fraud": "Identity Theft / Credential Misuse",
    "Phishing": "Phishing",
    "Online Harassment": "Online Harassment",
    "Cyberstalking": "Online Harassment",
    "Unauthorized Account Access": "Unauthorized Account Access",
    "Data Theft / Data Exposure": "Data Privacy and Security",
    "Malware / Malicious Software": "Malware / Malicious Software",
    "Cyber Extortion": "Cyber Extortion",
    "Fake Website / Online Scam": "Fake Website / Online Scam",
}

LEGAL_PROVISIONS = {
    "Financial Cyber Fraud": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "If the complainant was deceived into transferring money or providing access through a false digital identity, link, impersonation, or fraudulent request, section 66D may be relevant.",
            "facts_required": ["Money was lost or transferred", "A fraudulent request or impersonation was involved", "The transaction or communication was digital or online"],
            "evidence": ["Transaction ID", "UPI or bank details", "SMS/email screenshots", "Screenshots of messages or calls", "Bank statement or payment proof"]
        },
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "318",
            "title": "Cheating",
            "why_it_may_apply": "If dishonesty and deception caused a money transfer or property loss, this provision may be considered depending on the facts.",
            "facts_required": ["Deception or false representation", "Delivery or transfer of property or money", "Dishonest inducement"],
            "evidence": ["Payment records", "Messages showing inducement", "Bank proof", "Timeline of events"]
        }
    ],
    "UPI Fraud": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "If a fraudulent UPI request, QR code, or impersonation caused a payment without authority, section 66D may be relevant.",
            "facts_required": ["Fraudulent UPI or payment request", "Unauthorized transfer or QR request", "Deception involved"],
            "evidence": ["UPI transaction ID", "Screenshots of QR/request", "Bank statement", "Payment request screenshots", "SMS alerts"]
        },
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "318",
            "title": "Cheating",
            "why_it_may_apply": "This may be relevant where a false payment request was used to induce a transfer of funds or digital property.",
            "facts_required": ["Payment induced by deception", "Money or digital value transferred", "A fraudster benefited"],
            "evidence": ["Payment confirmation", "Messages or calls", "Transaction records", "Screenshots or call logs"]
        }
    ],
    "Phishing": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "Where a deceptive message or fake login portal induced the user to disclose OTPs, credentials, or personal data, this may be relevant.",
            "facts_required": ["Suspicious link or fake portal", "Credential or OTP was provided", "Deception or impersonation was involved"],
            "evidence": ["Original email or text message", "Suspicious URL", "Screenshots of the page", "Security alerts", "Date and time of the interaction"]
        },
        {
            "act": "Information Technology Act, 2000",
            "section": "66C",
            "title": "Punishment for identity theft",
            "why_it_may_apply": "If the fraud involved misuse of a password, OTP, or unique digital credential or identifier, section 66C may require consideration.",
            "facts_required": ["Credentials were compromised or misused", "A digital identity feature was used without authority", "The misuse facilitated the fraud"],
            "evidence": ["OTP screenshots", "Password reset alerts", "Account notifications", "Relevant communications", "Login logs"]
        }
    ],
    "OTP / Credential Fraud": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66C",
            "title": "Punishment for identity theft",
            "why_it_may_apply": "If the accused used an OTP, password, or similar digital credential without authorization, this section may be relevant.",
            "facts_required": ["OTP or password was shared or misused", "The credential belonged to the complainant or another person", "The misuse caused unauthorized access or payment"],
            "evidence": ["OTP screenshots", "SMS or email proof", "Account alerts", "Security notification screenshots", "Relevant messages"]
        },
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "When deception using a fake or unauthorized digital request caused the user to share credentials or authorize a transfer, this may also be relevant.",
            "facts_required": ["A deceptive digital request was made", "The user gave credentials or approved a transfer", "The request involved impersonation, fraud, or deceit"],
            "evidence": ["Screenshots of deceptive requests", "Messages, emails, calls", "Account changes", "Payment confirmations"]
        }
    ],
    "Identity Theft": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66C",
            "title": "Punishment for identity theft",
            "why_it_may_apply": "If another person used the complainant’s identity feature, password, OTP, or digital profile without authority, section 66C may be relevant.",
            "facts_required": ["Unlawful use of identity information", "Misuse of a unique identifier or account", "Harm or loss caused by the misuse"],
            "evidence": ["Screenshots of fake accounts", "Identity documents or alerts", "Messages showing impersonation", "Platform reports"]
        },
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "This may apply where identity was used to impersonate, deceive, or mislead another person to obtain money or trust.",
            "facts_required": ["Someone impersonated the complainant online", "The impersonation induced action or loss", "The digital impersonation was material to the conduct"],
            "evidence": ["Fake profile screenshots", "Messages", "Evidence of loss or harm", "Platform records"]
        }
    ],
    "Online Impersonation": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66C",
            "title": "Punishment for identity theft",
            "why_it_may_apply": "If a person used another person’s identity, photograph, or account details to impersonate them online, section 66C may be relevant depending on the facts.",
            "facts_required": ["A fake profile or account was created", "The complainant’s identity or photo was used", "The impersonation caused confusion, loss, or harm"],
            "evidence": ["Screenshots of the fake account", "Profile link or handle", "Messages asking for money or trust", "Proof of misuse or impersonation"]
        },
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "This section may be relevant when the impersonation was used to deceive others into transferring money, trusting the fake profile, or accepting false information.",
            "facts_required": ["The person was impersonated digitally", "The impersonation was used to deceive others", "A loss, transfer, or harmful action resulted"],
            "evidence": ["Fake account screenshots", "Communication logs", "Evidence of requests made in the victim’s name", "Platform complaints"]
        },
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "318",
            "title": "Cheating",
            "why_it_may_apply": "If the fake account or impersonation was used to fraudulently induce money, trust, or other benefit, this provision may also be reviewed.",
            "facts_required": ["A dishonest representation was made", "Money or property was induced by deception", "The impersonation was part of the fraud"],
            "evidence": ["Chat logs", "Payment or transfer records", "Screenshots of the fake account", "Evidence of deception"]
        }
    ],
    "Social Media Crime": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "If a fake social-media profile was created to deceive contacts or gain trust, this provision may be relevant.",
            "facts_required": ["Fake social media account was created", "The identity was misused or impersonated", "The impersonation caused harm or deception"],
            "evidence": ["Profile URL", "Username or handle", "Screenshots", "Chat messages", "Reports made to the platform"]
        },
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "351",
            "title": "Criminal intimidation",
            "why_it_may_apply": "If the online conduct included threatening or intrusive behaviour that caused fear or intimidation, this provision may merit review.",
            "facts_required": ["Threats or intimidation were involved", "The conduct caused fear or disturbance", "The communication was digital or online"],
            "evidence": ["Screenshots of threats", "Messages", "Witness statements", "Dates and times"]
        }
    ],
    "Unauthorized Account Access": [
        {
            "act": "Information Technology Act, 2000",
            "section": "43",
            "title": "Penalty and compensation for damage to computer, computer system, etc.",
            "why_it_may_apply": "If unauthorized access, alteration, or misuse of a computer resource caused damage or loss, this provision may be relevant.",
            "facts_required": ["Unauthorized access occurred", "A computer or account was accessed without consent", "There was resulting damage or loss"],
            "evidence": ["Access alerts", "Login history", "Security emails", "Device details", "Screenshots of account activity"]
        },
        {
            "act": "Information Technology Act, 2000",
            "section": "66",
            "title": "Computer-related offences",
            "why_it_may_apply": "If the unauthorized access involved dishonest or fraudulent conduct affecting a computer resource, this provision may be relevant depending on the facts.",
            "facts_required": ["A digital resource was accessed without authority", "The conduct was dishonest or fraudulent", "The access caused harm or misuse"],
            "evidence": ["Login activity", "Recovery emails", "Security logs", "Timeline of suspicious activity"]
        }
    ],
    "Online Harassment": [
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "351",
            "title": "Criminal intimidation",
            "why_it_may_apply": "Repeated threats, intimidation, or abusive conduct online may be considered under criminal-intimidation provisions depending on the facts.",
            "facts_required": ["Threatening or abusive messages", "Repetition or pattern of conduct", "Fear or intimidation caused"],
            "evidence": ["Screenshots of messages", "Dates and times", "Threat descriptions", "Chat history"]
        },
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "78",
            "title": "Stalking",
            "why_it_may_apply": "If the conduct involved repeated online follow-up, monitoring, or intimidation, stalking provisions may require evaluation.",
            "facts_required": ["Repeated contact or following", "Online monitoring or intimidation", "Fear or distress caused"],
            "evidence": ["Repeated message logs", "Screenshots", "Contact timeline", "Witness accounts"]
        }
    ],
    "Cyberstalking": [
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "78",
            "title": "Stalking",
            "why_it_may_apply": "Persistent online tracking, monitoring, or repeated intrusive contact may fall under stalking provisions depending on the specific facts.",
            "facts_required": ["Repeated online attention or monitoring", "Fear or disturbance caused", "Pattern of intrusive conduct"],
            "evidence": ["Chat logs", "Screenshots", "Timeline of contact", "Location or tracking evidence"]
        }
    ],
    "Data Theft / Data Exposure": [
        {
            "act": "Information Technology Act, 2000",
            "section": "43",
            "title": "Penalty and compensation for damage to computer, computer system, etc.",
            "why_it_may_apply": "If personal or sensitive data was accessed, exposed, or misused without consent, this provision may be relevant.",
            "facts_required": ["Data was accessed, leaked, or exposed", "The data was personal or sensitive", "Damage or risk was caused"],
            "evidence": ["Notices of leak", "Screenshots of data exposure", "Emails or alerts", "Timeline of disclosure"]
        },
        {
            "act": "Information Technology Act, 2000",
            "section": "72",
            "title": "Penalty for breach of confidentiality and privacy",
            "why_it_may_apply": "Where another person used or disclosed personal or confidential information improperly, this section may require consideration.",
            "facts_required": ["Confidential information was accessed or disclosed", "There was a breach of privacy or confidentiality", "The disclosure caused harm or risk"],
            "evidence": ["Communication showing disclosure", "Logs of access", "Screenshots or notices", "Relevant messages"]
        }
    ],
    "Malware / Malicious Software": [
        {
            "act": "Information Technology Act, 2000",
            "section": "43",
            "title": "Penalty and compensation for damage to computer, computer system, etc.",
            "why_it_may_apply": "Malware or malicious software that damages a device, steals information, or alters functionality may engage this provision depending on the facts.",
            "facts_required": ["Malicious file, link, or attachment was involved", "A device or system was harmed or compromised", "Unauthorized access or alteration occurred"],
            "evidence": ["Suspicious file or URL", "Antivirus alert", "Screenshots", "Device behaviour logs", "Download source"]
        }
    ],
    "Cyber Extortion": [
        {
            "act": "Bharatiya Nyaya Sanhita, 2023",
            "section": "308",
            "title": "Extortion",
            "why_it_may_apply": "If money or a benefit was demanded by threat, blackmail, or intimidation, this extortion provision may be relevant.",
            "facts_required": ["Threat or intimidation was used", "A demand for money or benefit was made", "The threat was linked to the demand"],
            "evidence": ["Threat messages", "Screenshots", "Payment requests", "Timeline of threats", "Phone or call records"]
        }
    ],
    "Fake Website / Online Scam": [
        {
            "act": "Information Technology Act, 2000",
            "section": "66D",
            "title": "Cheating by personation using computer resource",
            "why_it_may_apply": "If a fake website, cloned app, or deceptive digital platform induced the user into sharing money or credentials, this may be relevant.",
            "facts_required": ["A fake website or cloned page was used", "The user was deceived into acting", "Money, credentials, or information were transferred"],
            "evidence": ["URL of the fake website", "Screenshots", "Payment records", "Messages or emails", "Website copy or screenshots"]
        }
    ]
}


def default_session_state() -> Dict[str, Any]:
    return {
        "history": [],
        "answers": {},
        "asked_questions": [],
        "pending_question": None,
        "current_question": None,
        "original_complaint": "",
        "normalized_complaint": "",
        "detected_language": "English",
        "last_category": "Uncertain",
        "category_candidates": [],
        "confidence": 0,
        "current_stage": "new",
        "extracted_facts": [],
        "final_assessment": None,
        "last_response": "",
    }


def get_session_state(session_id: str) -> Dict[str, Any]:
    state = SESSION_STORE.setdefault(session_id, default_session_state())
    for key, value in default_session_state().items():
        if key not in state:
            state[key] = value
    return state


def extract_facts(normalized_text: str, category: Optional[str] = None) -> List[str]:
    facts: List[str] = []
    text = normalized_text or ""
    if "otp" in text or "password" in text:
        facts.append("Credential or OTP information was mentioned.")
    if "link" in text or "email" in text or "verification" in text:
        facts.append("A suspicious digital link, message, or verification request was reported.")
    if "money" in text or "payment" in text or "bank" in text or "transfer" in text or "upi" in text:
        facts.append("A financial transaction or money loss was described.")
    if "account" in text or "login" in text or "access" in text:
        facts.append("Account access or login activity was mentioned.")
    if "instagram" in text or "facebook" in text or "profile" in text or "fake" in text:
        facts.append("A fake profile, impersonation, or social-media misuse was described.")
    if "threat" in text or "blackmail" in text or "harass" in text:
        facts.append("Threats, intimidation, or online harassment were mentioned.")
    if category and facts:
        facts.insert(0, f"Incident pattern points to {category}.")
    return facts[:6]


def build_follow_up_question(category: str, state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    questions = QUESTION_BANK.get(category, QUESTION_BANK["default"])
    for question in questions:
        if question["question"] not in state.get("asked_questions", []):
            state["asked_questions"].append(question["question"])
            state["current_question"] = question
            state["pending_question"] = question
            return question
    return None


def detect_language(raw_text: str) -> Dict[str, Any]:
    text = (raw_text or "").strip()
    if not text:
        return {"language": "English", "confidence": 0.0, "normalized": ""}

    lowered = text.lower()
    if any(ch in text for ch in "ஐஎழஅஇஉஒகஙசஜஞடணதநமயரலவழஷஸஹளற"):
        return {"language": "Tamil", "confidence": 0.98, "normalized": normalize_multilingual_text(text, "ta")}
    if any(ch in text for ch in "अआइईउऊएऐओऔकखगघचछजझटठडढतथदधनपफबभमयरलवशषसहंः़"):
        return {"language": "Hindi", "confidence": 0.98, "normalized": normalize_multilingual_text(text, "hi")}

    tokens = {token.lower() for token in re.findall(r"[A-Za-z]+", text)}
    tamil_like = sum(1 for token in tokens if token in {
        "enakku", "pannirukanga", "illama", "irundhu", "poiduchu", "aagum",
        "vandhuchu", "andha", "pannadhukku", "apram", "aayiduchu", "nu",
        "oru", "la", "ah", "appo", "ungal", "ungalukku", "seithu",
        "seydhu", "thiruttu", "mosadi", "panam"
    })
    hindi_like = sum(1 for token in tokens if token in {
        "mere", "bina", "paise", "karke", "kisi", "mujhe", "mera", "nakli",
        "dhokha", "paisa", "khata", "bheja"
    })
    if tamil_like >= 2 or (tamil_like == 1 and len(tokens) <= 8):
        return {"language": "Tamil", "confidence": 0.84, "normalized": normalize_multilingual_text(text, "ta")}
    if hindi_like >= 2 or (hindi_like == 1 and len(tokens) <= 8):
        return {"language": "Hindi", "confidence": 0.84, "normalized": normalize_multilingual_text(text, "hi")}
    return {"language": "English", "confidence": 0.85, "normalized": normalize_multilingual_text(text, "en")}


def normalize_multilingual_text(raw_text: str, forced_lang: Optional[str] = None) -> str:
    text = (raw_text or "").lower()
    if forced_lang == "ta":
        for key, value in sorted(TAMIL_TO_ENGLISH.items(), key=lambda item: len(item[0]), reverse=True):
            text = re.sub(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])", value, text)
    elif forced_lang == "hi":
        for key, value in sorted(HINDI_TO_ENGLISH.items(), key=lambda item: len(item[0]), reverse=True):
            text = re.sub(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])", value, text)
    for key, value in sorted(ROMAN_TAMIL.items(), key=lambda item: len(item[0]), reverse=True):
        text = re.sub(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])", value, text)
    for key, value in sorted(ROMAN_HINDI.items(), key=lambda item: len(item[0]), reverse=True):
        text = re.sub(rf"(?<![a-z0-9]){re.escape(key)}(?![a-z0-9])", value, text)
    text = text.replace("&", " and ")
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    replacements = {
        "insta": "instagram",
        "fb": "facebook",
        "gpay": "google pay",
        "upi": "upi",
        "otp": "otp",
        "cvv": "cvv",
        "pin": "pin",
        "sms": "sms",
        "ig": "instagram",
        "id": "identity",
        "transfered": "transferred",
        "transferred": "transferred",
        "took": "took",
        "hack": "hack",
        "fakeprofile": "fake profile",
        "fakeaccount": "fake account",
        "withoutpermission": "without permission",
        "bankaccount": "bank account",
        "moneytransfer": "money transfer"
    }
    tokens = []
    for token in text.split():
        tokens.append(replacements.get(token, token))
    return " ".join(tokens)


def normalize_text(raw_text: str) -> str:
    language_info = detect_language(raw_text)
    return language_info["normalized"] or normalize_multilingual_text(raw_text, "en")


def localize_assistant_text(text: str, language: str, category: str = "") -> str:
    if language != "Tamil":
        return text
    if "need a little more information" in text.lower():
        return "இந்த சம்பவம் {} தொடர்பானதாக இருக்கலாம். தெளிவான சட்ட வழிகாட்டலுக்கு இன்னும் சில தகவல்கள் தேவை.".format(category or "சைபர் குற்றம்")
    if "appears to align with" in text.lower():
        return "நீங்கள் வழங்கிய தகவலின் அடிப்படையில், இந்த புகார் {} வகையுடன் தொடர்புடையதாகத் தெரிகிறது. இது ஆரம்பகட்ட மதிப்பீடு மட்டுமே; முழு விவரங்கள், ஆதாரங்கள் மற்றும் விசாரணையைப் பொறுத்தது.".format(category or "சைபர் குற்றம்")
    return text


def localize_question(question: Dict[str, Any], language: str, category: str) -> Dict[str, Any]:
    if language != "Tamil":
        return question
    tamil_questions = {
        "Financial Cyber Fraud": "உங்கள் அனுமதியின்றி உங்கள் வங்கி கணக்கிலிருந்து பணம் சென்றதா?",
        "Phishing": "சந்தேகமான செய்தியில் உள்ள இணைப்பை கிளிக் செய்தீர்களா அல்லது அதற்கு பதிலளித்தீர்களா?",
        "Identity Theft": "யாராவது உங்கள் தனிப்பட்ட விவரங்கள் அல்லது ஆவணங்களைப் பயன்படுத்துகிறார்களா?",
    }
    translated = dict(question)
    translated["question"] = tamil_questions.get(category, "இந்த சம்பவம் தொடர்பான ஸ்கிரீன்ஷாட்கள் அல்லது செய்திகள் உங்களிடம் உள்ளதா?")
    translated["options"] = ["ஆம்", "இல்லை", "தெரியவில்லை"]
    return translated


def score_category(category_name: str, normalized_text: str) -> Tuple[int, List[str]]:
    rules = CATEGORY_PATTERNS.get(category_name, {"strong": [], "medium": [], "weak": []})
    score = 0
    matched_indicators: List[str] = []
    for strength, phrases in rules.items():
        weight = {"strong": 30, "medium": 20, "weak": 10}[strength]
        for phrase in phrases:
            if phrase in normalized_text:
                score += weight
                matched_indicators.append(phrase)
    return score, matched_indicators


def classify_incident(text: str) -> Dict[str, Any]:
    normalized_text = normalize_text(text)
    scores: List[Dict[str, Any]] = []
    for category_name in CATEGORY_PATTERNS:
        category_score, matched_indicators = score_category(category_name, normalized_text)
        scores.append({
            "category": category_name,
            "score": category_score,
            "indicators": matched_indicators
        })

    alias_boosts = {
        "unauthorized access": "Unauthorized Account Access",
        "hacked my account": "Unauthorized Account Access",
        "account hacked": "Unauthorized Account Access",
        "someone hacked": "Unauthorized Account Access",
        "hacked my email": "Unauthorized Account Access",
        "hacked my social media": "Unauthorized Account Access",
        "someone logged into my account": "Unauthorized Account Access",
        "logged in from another device": "Unauthorized Account Access",
        "suspicious login": "Unauthorized Account Access",
        "someone used my password": "Unauthorized Account Access",
        "fake profile": "Social Media Crime",
        "impersonating me": "Social Media Crime",
        "pretending to be me": "Social Media Crime",
        "fake account using my name": "Social Media Crime",
        "created account in my name": "Social Media Crime",
        "fake instagram account": "Social Media Crime",
        "fake facebook account": "Social Media Crime",
        "using my photo": "Online Impersonation",
        "my photo was used": "Online Impersonation",
        "profile clone": "Online Impersonation",
        "fake account using my photo": "Online Impersonation",
        "cloned my profile": "Online Impersonation",
        "created fake account in my name": "Online Impersonation",
        "using my name and photos": "Online Impersonation",
        "blackmail": "Cyber Extortion",
        "extortion": "Cyber Extortion",
        "pay me or i will leak": "Cyber Extortion",
        "threatening to leak my photos": "Cyber Extortion",
        "threaten to expose me": "Cyber Extortion",
        "demanding money by threat": "Cyber Extortion",
        "stalking me": "Cyberstalking",
        "tracking my location": "Cyberstalking",
        "monitoring my activity": "Cyberstalking",
        "following me online": "Cyberstalking",
        "keeps watching my profile": "Cyberstalking",
        "data leaked": "Data Theft / Data Exposure",
        "photos leaked": "Data Theft / Data Exposure",
        "private data exposed": "Data Theft / Data Exposure",
        "documents leaked": "Data Theft / Data Exposure",
        "leaked my personal information": "Data Theft / Data Exposure",
        "my aadhaar leaked": "Data Theft / Data Exposure",
        "my pan was misused": "Identity Theft",
        "malware": "Malware / Malicious Software",
        "virus": "Malware / Malicious Software",
        "trojan": "Malware / Malicious Software",
        "ransomware": "Malware / Malicious Software",
        "spyware": "Malware / Malicious Software",
        "downloaded a malicious file": "Malware / Malicious Software",
        "fake website": "Fake Website / Online Scam",
        "clone website": "Fake Website / Online Scam",
        "online scam": "Fake Website / Online Scam",
        "fake app": "Fake Website / Online Scam",
        "fraudulent website": "Fake Website / Online Scam",
        "scam portal": "Fake Website / Online Scam",
        "upi fraud": "UPI Fraud",
        "upi transfer": "UPI Fraud",
        "qr code scam": "UPI Fraud",
        "gpay scam": "UPI Fraud",
        "phonepe scam": "UPI Fraud",
        "paytm fraud": "UPI Fraud",
        "otp stolen": "OTP / Credential Fraud",
        "password stolen": "OTP / Credential Fraud",
        "credentials leaked": "OTP / Credential Fraud",
        "otp was shared": "OTP / Credential Fraud",
        "my otp was used": "OTP / Credential Fraud",
        "someone used my security code": "OTP / Credential Fraud",
        "wallet drained": "Financial Cyber Fraud",
        "money transferred": "Financial Cyber Fraud",
        "money lost": "Financial Cyber Fraud",
        "lost money": "Financial Cyber Fraud",
        "unauthorized transaction": "Financial Cyber Fraud",
        "fraudulent payment request": "Financial Cyber Fraud",
        "bank account hacked": "Financial Cyber Fraud",
        "abusive messages": "Online Harassment",
        "harassing me online": "Online Harassment",
        "threatening messages": "Online Harassment",
        "repeated vulgar messages": "Online Harassment",
        "abusive whatsapp messages": "Online Harassment",
        "someone is bullying me online": "Online Harassment",
        "phishing": "Phishing",
        "suspicious link": "Phishing",
        "fake login page": "Phishing",
        "clicked a verification link": "Phishing",
        "entered otp on fake site": "Phishing",
        "identity theft": "Identity Theft",
        "using my identity": "Identity Theft",
        "using my documents": "Identity Theft",
        "using my aadhaar": "Identity Theft",
        "using my pan": "Identity Theft",
        "someone opened account in my name": "Identity Theft",
        "using my personal information": "Identity Theft",
    }

    for phrase, category_name in alias_boosts.items():
        if phrase in normalized_text:
            for item in scores:
                if item["category"] == category_name:
                    item["score"] += 35
                    item["indicators"].append(phrase)

    financial_keywords = (
        "money", "payment", "bank", "wallet", "upi", "transfer", "transferred",
        "withdrawal", "fraud", "debit", "account hacked", "bank account"
    )
    if any(keyword in normalized_text for keyword in financial_keywords):
        for item in scores:
            if item["category"] in {"Financial Cyber Fraud", "UPI Fraud", "OTP / Credential Fraud"}:
                item["score"] += 25

    suspicious_link_and_money = (
        ("link" in normalized_text or "clicked" in normalized_text or "verification" in normalized_text or "otp" in normalized_text)
        and ("money" in normalized_text or "transfer" in normalized_text or "bank" in normalized_text or "payment" in normalized_text)
    )
    if suspicious_link_and_money:
        for item in scores:
            if item["category"] in {"Financial Cyber Fraud", "Phishing", "UPI Fraud"}:
                item["score"] += 40
                item["indicators"].append("suspicious link and money transfer")

    scores.sort(key=lambda item: item["score"], reverse=True)
    top = scores[0]
    runner_up_score = scores[1]["score"] if len(scores) > 1 else 0
    score_strength = min(80, top["score"])
    score_margin = max(0, top["score"] - runner_up_score)
    confidence = min(95, max(0, int(score_strength * 0.75 + min(40, score_margin) * 0.25)))
    if suspicious_link_and_money and top["category"] in {"Financial Cyber Fraud", "Phishing", "UPI Fraud"}:
        needs_followup = True
    elif top["score"] >= 70 or len(top["indicators"]) >= 2:
        needs_followup = False
    elif top["score"] >= 40:
        needs_followup = True
    else:
        needs_followup = True
    response = (
        "This pattern may involve {}. I need a little more information before providing detailed guidance.".format(top["category"])
    )
    return {
        "category": top["category"],
        "confidence": confidence,
        "indicators": top["indicators"],
        "needs_followup": needs_followup,
        "response": response,
        "text": normalized_text,
    }


def determine_confidence_label(confidence: int) -> str:
    if confidence <= 39:
        return "Low Confidence"
    if confidence <= 69:
        return "Medium Confidence"
    return "High Confidence"


def determine_urgency(category: str, normalized_text: str) -> str:
    critical_terms = ("unauthorized transaction", "money was taken", "stolen money", "upi transaction", "account was hacked")
    high_terms = ("blackmail", "threat", "impersonat", "logged into my account", "password stopped working")
    if any(term in normalized_text for term in critical_terms):
        return "CRITICAL"
    if any(term in normalized_text for term in high_terms) or category in {"Identity Theft", "Online Impersonation", "Cyber Extortion"}:
        return "HIGH"
    if category != "Uncertain":
        return "MEDIUM"
    return "LOW"


def get_question_for_category(category_name: str, session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    questions = QUESTION_BANK.get(category_name, QUESTION_BANK["default"])
    asked = session.get("asked_questions", [])
    for question in questions:
        if question["question"] not in asked:
            asked.append(question["question"])
            session["asked_questions"] = asked
            session["pending_question"] = question
            return question
    return None


def normalize_answer(answer: str) -> str:
    cleaned = answer.strip().lower()
    if not cleaned:
        return "not sure"
    if cleaned in {"yes", "y", "yeah", "sure", "ஆம்"}:
        return "Yes"
    if cleaned in {"no", "n", "nope", "இல்லை"}:
        return "No"
    if cleaned in {"not sure", "unsure", "maybe", "idk", "தெரியவில்லை"}:
        return "Not sure"
    return answer.strip()


def build_final_result(category_name: Optional[str] = None, category: Optional[str] = None, confidence: int = 0, indicators: Optional[List[str]] = None, original_text: str = "", session: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    category_name = category_name or category or "Financial Cyber Fraud"
    indicators = indicators or []
    session = session or {}
    legal_content = LEGAL_GUIDANCE_MAP.get(category_name, LEGAL_GUIDANCE_MAP.get("Financial Cyber Fraud"))
    if not legal_content:
        legal_content = {
            "category": category_name,
            "description": "The category is being reviewed based on the complaint pattern.",
            "relevant_indian_law": "Preliminary guidance only. The specific legal route depends on the facts and jurisdiction.",
            "general_legal_explanation": "This is a preliminary categorization and should be reviewed by a qualified legal professional.",
            "potential_consequences": ["Possible civil or criminal consequences depending on the facts."],
            "evidence_recommendations": ["Relevant screenshots, messages, account records, and documents."],
            "reporting_guidance": ["Preserve evidence and contact the relevant service provider or official channel."],
            "disclaimer": "This information is preliminary educational guidance and is not a substitute for advice from a qualified legal professional."
        }

    evidence = legal_content.get("evidence_recommendations", ["Relevant screenshots, messages, account records, and documents."])
    next_steps = legal_content.get("reporting_guidance", ["Preserve evidence and contact the appropriate authority."])
    if category_name in {"Financial Cyber Fraud", "UPI Fraud", "OTP / Credential Fraud"}:
        urgent_action = "If money was transferred, consider urgent financial reporting channels and official fraud reporting contacts. In India, 1930 is commonly referenced for financial fraud reporting where applicable."
        if urgent_action not in next_steps:
            next_steps.insert(0, urgent_action)
    legal_provisions = []
    relevant_law_text = []
    for item in legal_provisions[:3]:
        relevant_law_text.append({
            "act": item.get("act"),
            "section": item.get("section"),
            "title": item.get("title"),
            "why_it_may_apply": item.get("why_it_may_apply"),
            "facts_required": item.get("facts_required", []),
            "evidence": item.get("evidence", [])
        })

    applicable_law_summary = []
    for item in relevant_law_text:
        section_value = item.get("section") or "Applicable provision"
        title_value = item.get("title") or "Cybercrime/legal provision"
        applicable_law_summary.append({
            "act": item.get("act") or "Applicable Indian law",
            "section": section_value,
            "title": title_value,
            "reason": item.get("why_it_may_apply") or "Relevant based on the facts described."
        })

    language = detect_language(original_text).get("language", "English")
    summary = (
        "Based on the information provided, this complaint appears to align with {}. "
        "The assessment is preliminary and depends on the facts, evidence, and investigation."
    ).format(category_name)
    summary = localize_assistant_text(summary, language, category_name)
    session["finalized_report"] = {
        "complaint": original_text,
        "category": category_name,
        "confidence": confidence,
        "indicators": indicators,
        "answers": session.get("answers", {}),
    }
    related = RELATED_CATEGORY_MAP.get(category_name, category_name)
    return {
        "type": "final",
        "language": language,
        "category": category_name,
        "related_category": related,
        "confidence": confidence,
        "confidence_label": determine_confidence_label(confidence),
        "urgency": determine_urgency(category_name, normalize_text(original_text)),
        "indicators": indicators,
        "legal_guidance": {
            "category": legal_content.get("category", category_name),
            "description": legal_content.get("description", ""),
            "relevant_indian_law": legal_content.get("relevant_indian_law", ""),
            "general_legal_explanation": legal_content.get("general_legal_explanation", ""),
            "potential_consequences": legal_content.get("potential_consequences", []),
            "disclaimer": legal_content.get("disclaimer", "This information is preliminary educational guidance and is not a substitute for advice from a qualified legal professional."),
            "applicable_laws": applicable_law_summary,
            "legal_provisions": applicable_law_summary
        },
        "legal_provisions": relevant_law_text,
        "applicable_laws": applicable_law_summary,
        "possible_applicable_law": applicable_law_summary[0]["act"] + " — Section " + applicable_law_summary[0]["section"] if applicable_law_summary else "Preliminary legal review required.",
        "evidence": evidence,
        "next_steps": next_steps,
        "response": summary,
        "facts": extract_facts(normalize_text(original_text), category_name),
        "disclaimer": "This assessment is preliminary and not a final legal determination. The exact legal classification depends on the facts, evidence and investigation.",
    }


INCIDENT_TYPES_BY_CATEGORY = {
    "Financial Cyber Fraud": ["Phishing-based bank fraud", "UPI fraud", "Fake bank or customer-care scam", "Unauthorized transaction"],
    "Phishing": ["Fake login page", "Fraudulent email or SMS", "Credential or OTP harvesting", "Malicious verification link"],
    "Identity Theft": ["Misuse of identity documents", "Account opened in another person's name", "Stolen credentials", "Identity used for fraud"],
    "Social Media Crime": ["Fake social-media profile", "Abusive or threatening messages", "Fraudulent outreach", "Account or content misuse"],
    "Unauthorized Account Access": ["Account takeover", "Unauthorized login", "Password compromise", "Suspicious device or session"],
    "Online Harassment": ["Repeated abusive messages", "Online threats", "Public shaming", "Targeted bullying"],
    "Data Theft / Data Exposure": ["Personal data leak", "Unauthorized database access", "Private files exposed", "Sensitive information misuse"],
    "Cyberstalking": ["Repeated online monitoring", "Location tracking", "Unwanted repeated contact", "Threatening surveillance"],
    "Online Impersonation": ["Fake profile", "Using another person's photo or name", "Impersonation for money", "Cloned account"],
    "Malware / Malicious Software": ["Malicious attachment", "Trojan or spyware", "Ransomware", "Compromised device"],
    "Cyber Extortion": ["Blackmail", "Threat to publish private material", "Ransom demand", "Threat-based payment request"],
    "Fake Website / Online Scam": ["Cloned website", "Fake shopping portal", "Fraudulent app", "Scam service provider"],
    "UPI Fraud": ["Fake UPI collect request", "QR-code scam", "Unauthorized UPI payment", "Payment-app impersonation"],
    "OTP / Credential Fraud": ["OTP theft", "Password theft", "Fake KYC request", "Credential harvesting"],
}

URGENCY_BY_CATEGORY = {
    "Financial Cyber Fraud": ("HIGH", "An unauthorized or deceptive financial transaction may require immediate bank and reporting action."),
    "UPI Fraud": ("HIGH", "A UPI or payment-app transaction can be difficult to reverse without prompt reporting."),
    "OTP / Credential Fraud": ("HIGH", "Compromised credentials can enable immediate account takeover or financial loss."),
    "Unauthorized Account Access": ("HIGH", "An active unauthorized session may expose accounts and connected data."),
    "Identity Theft": ("MEDIUM-HIGH", "Identity misuse can lead to continuing financial, account, and reputational harm."),
    "Malware / Malicious Software": ("MEDIUM-HIGH", "A compromised device may continue leaking data or credentials."),
    "Cyber Extortion": ("MEDIUM-HIGH", "Threats and demands can escalate and may create an immediate safety concern."),
    "Online Harassment": ("MEDIUM-HIGH", "Threatening or repeated communications should be preserved and reported promptly."),
    "Cyberstalking": ("MEDIUM-HIGH", "Persistent monitoring or threats may create an ongoing personal safety concern."),
}

def build_legal_guidance_categories() -> List[Dict[str, Any]]:
    enriched_categories = []
    for source in LEGAL_DATA.get("categories", []):
        category = dict(source)
        category_name = category.get("category", "Unknown category")
        category["incident_types"] = INCIDENT_TYPES_BY_CATEGORY.get(category_name, ["Online incident requiring fact-specific review"])
        category["provisions"] = []
        category["evidence_to_preserve"] = category.get("evidence_recommendations", [])
        category["urgency_level"], category["urgency_reason"] = URGENCY_BY_CATEGORY.get(category_name, ("MEDIUM", "The response priority depends on the reported facts, harm, and ongoing risk."))
        category["immediate_actions"] = category.get("reporting_guidance", [])[:4]
        category["do_evidence"] = ["Preserve original messages, files, and links where possible.", "Record URLs, dates, times, transaction IDs, and reference numbers.", "Keep an unchanged copy of relevant evidence and the original device where feasible."]
        category["dont_evidence"] = ["Do not delete suspicious messages or edit the only copy.", "Do not forward evidence unnecessarily or continue engaging with the suspected person.", "Do not share OTPs, passwords, or banking credentials."]
        category["evidence_record_note"] = "Protect Evidence records the source, capture time, original file status, and integrity hash for a later evidence review."
        enriched_categories.append(category)
    return enriched_categories


def get_db_connection():
    db_type = (os.getenv("DB_TYPE") or "sqlite").lower()
    if db_type == "mysql":
        try:
            conn = mysql.connector.connect(
                host=os.getenv("DB_HOST", "localhost"),
                port=int(os.getenv("DB_PORT", "3306")),
                user=os.getenv("DB_USER", "root"),
                password=os.getenv("DB_PASSWORD", ""),
                database=os.getenv("DB_NAME", "cyberlegal"),
                autocommit=True,
                charset="utf8mb4",
                use_pure=True,
            )
            return conn, "mysql"
        except Exception as exc:
            app.logger.warning("MySQL not available, falling back to SQLite: %s", exc)

    conn = sqlite3.connect(app.config["DATABASE"])
    conn.row_factory = sqlite3.Row
    return conn, "sqlite"


def ensure_user_auth_columns() -> None:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        if db_type == "mysql":
            cursor.execute("DESCRIBE users")
            columns = [row[0] for row in cursor.fetchall()]
            if "username" not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN username VARCHAR(80) UNIQUE")
            if "password_hash" not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255)")
        else:
            cursor.execute("PRAGMA table_info(users)")
            columns = [row[1] for row in cursor.fetchall()]
            if "username" not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN username TEXT")
            if "password_hash" not in columns:
                cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        conn.close()


def ensure_report_columns() -> None:
    """Add report fields to databases created by an earlier project version."""
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        if db_type == "mysql":
            cursor.execute("DESCRIBE reports")
            columns = {row[0] for row in cursor.fetchall()}
            additions = {
                "report_ref": "VARCHAR(40) UNIQUE",
                "related_category": "VARCHAR(160)",
                "urgency": "VARCHAR(20) DEFAULT 'LOW'",
                "session_id": "VARCHAR(80)",
                "user_id": "INT DEFAULT 0",
                "assessment_json": "TEXT",
            }
            for name, definition in additions.items():
                if name not in columns:
                    cursor.execute(f"ALTER TABLE reports ADD COLUMN {name} {definition}")
        else:
            cursor.execute("PRAGMA table_info(reports)")
            columns = {row[1] for row in cursor.fetchall()}
            additions = {
                "report_ref": "TEXT",
                "related_category": "TEXT",
                "urgency": "TEXT DEFAULT 'LOW'",
                "session_id": "TEXT",
                "user_id": "INTEGER DEFAULT 0",
                "assessment_json": "TEXT",
            }
            for name, definition in additions.items():
                if name not in columns:
                    cursor.execute(f"ALTER TABLE reports ADD COLUMN {name} {definition}")
        conn.commit()
    finally:
        conn.close()


def initialize_database() -> None:
    conn, db_type = get_db_connection()
    try:
        with open(DB_SCHEMA_PATH, "r", encoding="utf-8") as file:
            schema_sql = file.read()
        if db_type == "mysql":
            statements = [item.strip() for item in schema_sql.split(";") if item.strip()]
            cursor = conn.cursor()
            for statement in statements:
                cursor.execute(statement)
        else:
            conn.executescript(schema_sql)
        conn.commit()
    finally:
        conn.close()
    ensure_user_auth_columns()
    ensure_report_columns()

    conn, _ = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS chat_sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE, user_id INTEGER DEFAULT 0, complaint TEXT, detected_category TEXT, confidence INTEGER DEFAULT 0, status TEXT DEFAULT 'Active', detected_language TEXT DEFAULT 'English', normalized_text TEXT, analysis_json TEXT, title TEXT, keywords TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        cursor.execute("CREATE TABLE IF NOT EXISTS chat_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, role TEXT, message TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()
    finally:
        conn.close()
    ensure_chat_session_columns()


def ensure_chat_session_columns() -> None:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        if db_type == "mysql":
            cursor.execute("DESCRIBE chat_sessions")
            columns = {row[0] for row in cursor.fetchall()}
            if "user_id" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN user_id INT DEFAULT 0")
            if "analysis_json" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN analysis_json TEXT")
            if "title" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN title VARCHAR(255)")
            if "keywords" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN keywords TEXT")
            if "updated_at" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN updated_at DATETIME")
        else:
            cursor.execute("PRAGMA table_info(chat_sessions)")
            columns = {row[1] for row in cursor.fetchall()}
            if "user_id" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN user_id INTEGER DEFAULT 0")
            if "analysis_json" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN analysis_json TEXT")
            if "title" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN title TEXT")
            if "keywords" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN keywords TEXT")
            if "updated_at" not in columns:
                cursor.execute("ALTER TABLE chat_sessions ADD COLUMN updated_at TEXT")
        cursor.execute(
            "UPDATE chat_sessions SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)"
        )
        cursor.execute(
            "UPDATE chat_sessions SET title = substr(complaint, 1, 255) "
            "WHERE title IS NULL AND complaint IS NOT NULL"
        )
        cursor.execute(
            "UPDATE chat_sessions SET keywords = '[]' WHERE keywords IS NULL"
        )
        cursor.execute(
            "SELECT session_id, complaint, analysis_json FROM chat_sessions "
            "WHERE keywords = '[]' OR keywords = ''"
        )
        legacy_sessions = cursor.fetchall()
        for row in legacy_sessions:
            legacy_analysis = safe_json_load(row[2], {})
            keywords = serialize_json_field(
                _chat_keywords(row[1] or "", legacy_analysis)
            )
            placeholder = "%s" if db_type == "mysql" else "?"
            cursor.execute(
                f"UPDATE chat_sessions SET keywords = {placeholder} WHERE session_id = {placeholder}",
                (keywords, row[0]),
            )
        cursor.execute(
            "SELECT session_id, complaint FROM chat_sessions "
            "WHERE normalized_text IS NULL OR normalized_text = complaint"
        )
        legacy_normalized_text = cursor.fetchall()
        for row in legacy_normalized_text:
            placeholder = "%s" if db_type == "mysql" else "?"
            cursor.execute(
                f"UPDATE chat_sessions SET normalized_text = {placeholder} WHERE session_id = {placeholder}",
                (normalize_text(row[1] or ""), row[0]),
            )
        conn.commit()
    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        if db_type == "mysql":
            cursor.execute("SELECT id, full_name, username, password_hash FROM users WHERE username = %s LIMIT 1", (username,))
        else:
            cursor.execute("SELECT id, full_name, username, password_hash FROM users WHERE username = ? LIMIT 1", (username,))
        row = cursor.fetchone()
        if not row:
            return None
        if db_type == "mysql":
            return {
                "id": row[0],
                "full_name": row[1],
                "username": row[2],
                "password_hash": row[3],
            }
        return {
            "id": row[0],
            "full_name": row[1],
            "username": row[2],
            "password_hash": row[3],
        }
    finally:
        conn.close()


def create_new_user(full_name: str, username: str, password: str) -> Dict[str, Any]:
    full_name = (full_name or "").strip()
    username = (username or "").strip()
    password = password or ""

    if not full_name:
        raise ValueError("Please provide your full name.")
    if not username:
        raise ValueError("Please choose a username.")
    if len(username) < 3:
        raise ValueError("Username must be at least 3 characters long.")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+", username):
        raise ValueError("Username can only contain letters, numbers, and . _ @ - characters.")
    if len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    if username.lower() == APP_USERNAME.lower():
        raise ValueError("This username is reserved for the default admin account.")
    if get_user_by_username(username):
        raise ValueError("This username already exists. Please choose another one.")

    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        password_hash = generate_password_hash(password)
        if db_type == "mysql":
            cursor.execute(
                "INSERT INTO users (full_name, username, password_hash) VALUES (%s, %s, %s)",
                (full_name, username, password_hash),
            )
            user_id = cursor.lastrowid
        else:
            cursor.execute(
                "INSERT INTO users (full_name, username, password_hash) VALUES (?, ?, ?)",
                (full_name, username, password_hash),
            )
            user_id = cursor.lastrowid
        conn.commit()
        return {"id": user_id, "full_name": full_name, "username": username}
    finally:
        conn.close()


def generate_session_id() -> str:
    stamp = datetime.now().strftime("%Y%m%d")
    return f"CLA-{stamp}-{uuid.uuid4().hex.upper()}"


def _chat_title(complaint: str) -> str:
    normalized = " ".join((complaint or "").split())
    return normalized[:120] or "New assessment"


def _chat_keywords(complaint: str, analysis: Optional[Dict[str, Any]] = None) -> List[str]:
    source_parts = [complaint]
    if isinstance(analysis, dict):
        assessment_parts = [
            str(analysis.get(key) or "")
            for key in ("category", "crime_type", "summary")
        ]
        for key in ("facts", "indicators", "missing_information"):
            values = analysis.get(key)
            if isinstance(values, list):
                assessment_parts.extend(str(value) for value in values)
        source_parts = assessment_parts + source_parts

    stop_words = {
        "about", "after", "again", "been", "before", "being", "from", "have",
        "into", "just", "more", "most", "other", "some", "that", "their",
        "there", "these", "they", "this", "through", "under", "very", "what",
        "when", "where", "which", "with", "would", "your", "எனக்கு", "என்று",
        "என்னுடைய", "அது", "இது",
    }
    keywords: List[str] = []
    seen = set()
    for part in source_parts:
        for word in re.findall(r"[^\W_]{3,}", part.casefold(), flags=re.UNICODE):
            if word in stop_words or word in seen:
                continue
            seen.add(word)
            keywords.append(word)
            if len(keywords) >= 30:
                return keywords
    return keywords


def create_chat_session(session_id: Optional[str], complaint: str, language: str, category: str = "Uncertain", confidence: int = 0, user_id: int = 0) -> str:
    final_id = session_id or generate_session_id()
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        if db_type == "mysql":
            cursor.execute(
                "INSERT INTO chat_sessions (session_id, complaint, detected_category, confidence, status, detected_language, normalized_text, created_at, user_id, title, keywords, updated_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (final_id, complaint, category, confidence, "Active", language, normalize_text(complaint), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_id, _chat_title(complaint), serialize_json_field(_chat_keywords(complaint)), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            )
        else:
            cursor.execute(
                "INSERT INTO chat_sessions (session_id, complaint, detected_category, confidence, status, detected_language, normalized_text, created_at, user_id, title, keywords, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (final_id, complaint, category, confidence, "Active", language, normalize_text(complaint), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user_id, _chat_title(complaint), serialize_json_field(_chat_keywords(complaint)), datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            )
        conn.commit()
        return final_id
    finally:
        conn.close()


def get_chat_session_owner(session_id: str) -> Optional[int]:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "mysql" else "?"
        cursor.execute(f"SELECT user_id FROM chat_sessions WHERE session_id = {placeholder} LIMIT 1", (session_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return int(row[0] or 0)
    finally:
        conn.close()


def update_chat_session_analysis(
    session_id: str,
    category: str,
    confidence: int,
    status: str,
    language: str,
    analysis: Dict[str, Any],
) -> None:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "mysql" else "?"
        cursor.execute(
            f"SELECT complaint FROM chat_sessions WHERE session_id = {placeholder}",
            (session_id,),
        )
        row = cursor.fetchone()
        complaint = row[0] if row else ""
        keywords = serialize_json_field(_chat_keywords(complaint, analysis))
        cursor.execute(
            f"UPDATE chat_sessions SET detected_category = {placeholder}, confidence = {placeholder}, status = {placeholder}, detected_language = {placeholder}, analysis_json = {placeholder}, title = {placeholder}, keywords = {placeholder}, updated_at = {placeholder} WHERE session_id = {placeholder}",
            (category, confidence, status, language, serialize_json_field(analysis), _chat_title(complaint), keywords, datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), session_id),
        )
        conn.commit()
    finally:
        conn.close()


def save_chat_message(session_id: str, role: str, message: str) -> None:
    if not session_id or not message:
        return
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if db_type == "mysql":
            cursor.execute("INSERT INTO chat_messages (session_id, role, message, created_at) VALUES (%s, %s, %s, %s)", (session_id, role, message, timestamp))
        else:
            cursor.execute("INSERT INTO chat_messages (session_id, role, message, created_at) VALUES (?, ?, ?, ?)", (session_id, role, message, timestamp))
        placeholder = "%s" if db_type == "mysql" else "?"
        cursor.execute(
            f"UPDATE chat_sessions SET updated_at = {placeholder} WHERE session_id = {placeholder}",
            (datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"), session_id),
        )
        conn.commit()
    finally:
        conn.close()


def _assessment_status(status: str) -> str:
    if status in {"Complete", "Follow-up"}:
        return "Assessed"
    if status == "Analysis unavailable":
        return "Failed"
    return "Pending"


def fetch_chat_sessions(user_id: Optional[int] = None, search_query: str = "") -> List[Dict[str, Any]]:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "mysql" else "?"
        fields = (
            "COALESCE(cs.title, '')",
            "COALESCE(cs.complaint, '')",
            "COALESCE(cs.normalized_text, '')",
            "COALESCE(cs.detected_category, '')",
            "COALESCE(cs.keywords, '')",
            "COALESCE(cs.session_id, '')",
        )
        conditions = []
        params: List[Any] = []
        if user_id is not None:
            conditions.append(f"cs.user_id = {placeholder}")
            params.append(user_id)
        tokens = list(dict.fromkeys(
            [token for token in search_query.strip()[:200].split() if token]
            + [token for token in normalize_text(search_query.strip()[:200]).split() if token]
        ))
        for token in tokens[:10]:
            pattern = f"%{token}%"
            token_fields = [
                f"LOWER({field}) LIKE LOWER({placeholder})" for field in fields
            ]
            token_fields.append(
                "EXISTS (SELECT 1 FROM reports r WHERE r.session_id = cs.session_id "
                f"AND r.user_id = cs.user_id AND (LOWER(COALESCE(r.report_ref, '')) LIKE LOWER({placeholder}) "
                f"OR LOWER(CAST(r.id AS CHAR)) LIKE LOWER({placeholder})))"
            )
            conditions.append("(" + " OR ".join(token_fields) + ")")
            params.extend([pattern] * (len(fields) + 2))
        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        query = (
            "SELECT cs.session_id, cs.complaint, cs.detected_category, cs.confidence, "
            "cs.status, cs.detected_language, cs.created_at, cs.title, cs.keywords, "
            "cs.updated_at, (SELECT r.report_ref FROM reports r "
            "WHERE r.session_id = cs.session_id AND r.user_id = cs.user_id "
            "ORDER BY r.created_at DESC LIMIT 1) AS report_ref, "
            "(SELECT r.id FROM reports r WHERE r.session_id = cs.session_id "
            "AND r.user_id = cs.user_id ORDER BY r.created_at DESC LIMIT 1) AS report_id "
            f"FROM chat_sessions cs{where} ORDER BY COALESCE(cs.updated_at, cs.created_at) DESC"
        )
        cursor.execute(query, tuple(params))
        rows = cursor.fetchall()
        sessions = []
        for row in rows:
            keywords = safe_json_load(row[8], [])
            if not isinstance(keywords, list):
                keywords = []
            sessions.append({
                "session_id": row[0],
                "complaint": row[1],
                "detected_category": row[2],
                "confidence": row[3],
                "status": row[4],
                "assessment_status": _assessment_status(row[4]),
                "detected_language": row[5],
                "created_at": row[6],
                "title": row[7] or _chat_title(row[1] or ""),
                "keywords": keywords,
                "updated_at": row[9] or row[6],
                "report_ref": row[10],
                "report_id": row[11],
            })
        return sessions
    finally:
        conn.close()


def fetch_chat_session_by_id(session_id: str, user_id: Optional[int] = None) -> Dict[str, Any]:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "mysql" else "?"
        if user_id is None:
            cursor.execute(
                f"SELECT session_id, complaint, detected_category, confidence, status, detected_language, normalized_text, created_at, analysis_json, title, keywords, updated_at, user_id FROM chat_sessions WHERE session_id = {placeholder} LIMIT 1",
                (session_id,),
            )
        else:
            cursor.execute(
                f"SELECT session_id, complaint, detected_category, confidence, status, detected_language, normalized_text, created_at, analysis_json, title, keywords, updated_at, user_id FROM chat_sessions WHERE session_id = {placeholder} AND user_id = {placeholder} LIMIT 1",
                (session_id, user_id),
            )
        row = cursor.fetchone()
        if not row:
            return {"messages": []}
        cursor.execute(
            f"SELECT role, message, created_at FROM chat_messages WHERE session_id = {placeholder} ORDER BY id ASC",
            (session_id,),
        )
        messages = cursor.fetchall()
        keywords = safe_json_load(row[10], [])
        if not isinstance(keywords, list):
            keywords = []
        related_reports = fetch_reports(int(row[12] or 0))
        related_reports = [
            {
                "id": item["id"],
                "report_ref": item["report_ref"],
                "created_at": item["created_at"],
                "status": item["status"],
                "detected_category": item["detected_category"],
            }
            for item in related_reports
            if item.get("session_id") == session_id
        ]
        return {
            "session_id": row[0],
            "complaint": row[1],
            "detected_category": row[2],
            "confidence": row[3],
            "status": row[4],
            "assessment_status": _assessment_status(row[4]),
            "detected_language": row[5],
            "normalized_text": row[6],
            "created_at": row[7],
            "analysis": safe_json_load(row[8], {}),
            "title": row[9] or _chat_title(row[1] or ""),
            "keywords": keywords,
            "updated_at": row[11] or row[7],
            "related_reports": related_reports,
            "messages": [{"role": msg[0], "message": msg[1], "created_at": msg[2]} for msg in messages],
        }
    finally:
        conn.close()


def build_report_id() -> str:
    now = datetime.now()
    return f"CLR-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"


def serialize_json_field(value: Any) -> str:
    if value is None:
        if isinstance(value, dict):
            return "{}"
        return "[]"
    return json.dumps(value, ensure_ascii=False)


def safe_json_load(value: Any, default: Any = None) -> Any:
    if value in (None, "", "null"):
        return default
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _safe_saved_assessment(value: Any, category: str) -> Dict[str, Any]:
    assessment = safe_json_load(value, {})
    if not isinstance(assessment, dict):
        return {}
    safe_assessment = dict(assessment)
    safe_assessment["legal_guidance"] = _legal_guidance_for_category(category)
    safe_assessment["legal_provisions"] = []
    safe_assessment["applicable_laws"] = []
    return safe_assessment


def save_report(report_data: Dict[str, Any]) -> int:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        user_id = report_data.get("user_id", 0)
        if db_type == "mysql":
            query = """
                INSERT INTO reports (report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, user_id, assessment_json)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor.execute(
                query,
                (
                    report_data.get("report_ref") or build_report_id(), report_data.get("complaint", ""),
                    report_data.get("category", "Uncertain"),
                    report_data.get("related_category", ""),
                    report_data.get("confidence", 0),
                    report_data.get("urgency", "LOW"),
                    serialize_json_field(report_data.get("indicators", [])),
                    serialize_json_field(report_data.get("answers", {})),
                    serialize_json_field(report_data.get("legal_guidance", {})),
                    serialize_json_field(report_data.get("evidence", [])),
                    serialize_json_field(report_data.get("next_steps", [])),
                    report_data.get("session_id", ""),
                    report_data.get("status", "Saved"),
                    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    user_id,
                    serialize_json_field(report_data.get("assessment", {})),
                )
            )
            report_id = cursor.lastrowid
        else:
            query = """
                INSERT INTO reports (report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, user_id, assessment_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(
                query,
                (
                    report_data.get("report_ref") or build_report_id(), report_data.get("complaint", ""),
                    report_data.get("category", "Uncertain"),
                    report_data.get("related_category", ""),
                    report_data.get("confidence", 0),
                    report_data.get("urgency", "LOW"),
                    serialize_json_field(report_data.get("indicators", [])),
                    serialize_json_field(report_data.get("answers", {})),
                    serialize_json_field(report_data.get("legal_guidance", {})),
                    serialize_json_field(report_data.get("evidence", [])),
                    serialize_json_field(report_data.get("next_steps", [])),
                    report_data.get("session_id", ""),
                    report_data.get("status", "Saved"),
                    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                    user_id,
                    serialize_json_field(report_data.get("assessment", {})),
                )
            )
            report_id = cursor.lastrowid
        conn.commit()
        return report_id
    finally:
        conn.close()


def find_report_for_assessment(session_id: str, user_id: int, assessment: Dict[str, Any]) -> Optional[int]:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "mysql" else "?"
        cursor.execute(
            f"SELECT id, assessment_json FROM reports WHERE session_id = {placeholder} "
            f"AND user_id = {placeholder} ORDER BY created_at DESC",
            (session_id, user_id),
        )
        for row in cursor.fetchall():
            if safe_json_load(row[1], {}) == assessment:
                return int(row[0])
        return None
    finally:
        conn.close()


def fetch_reports(user_id: Optional[int] = None) -> List[Dict[str, Any]]:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        if user_id is not None:
            if db_type == "mysql":
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
            else:
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
        else:
            if db_type == "mysql":
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports ORDER BY created_at DESC")
            else:
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports ORDER BY created_at DESC")
        rows = cursor.fetchall()
        reports = []
        for row in rows:
            reports.append({
                "id": row["id"] if isinstance(row, sqlite3.Row) else row[0],
                "report_ref": row["report_ref"] if isinstance(row, sqlite3.Row) else row[1],
                "complaint": row["complaint"] if isinstance(row, sqlite3.Row) else row[2],
                "detected_category": row["detected_category"] if isinstance(row, sqlite3.Row) else row[3],
                "related_category": row["related_category"] if isinstance(row, sqlite3.Row) else row[4],
                "confidence": row["confidence"] if isinstance(row, sqlite3.Row) else row[5],
                "urgency": row["urgency"] if isinstance(row, sqlite3.Row) else row[6],
                "indicators": safe_json_load(row["indicators"] if isinstance(row, sqlite3.Row) else row[7], []),
                "follow_up_answers": safe_json_load(row["follow_up_answers"] if isinstance(row, sqlite3.Row) else row[8], {}),
                "legal_guidance": _legal_guidance_for_category(row["detected_category"] if isinstance(row, sqlite3.Row) else row[3]),
                "evidence": safe_json_load(row["evidence"] if isinstance(row, sqlite3.Row) else row[10], []),
                "next_steps": safe_json_load(row["next_steps"] if isinstance(row, sqlite3.Row) else row[11], []),
                "session_id": row["session_id"] if isinstance(row, sqlite3.Row) else row[12],
                "status": row["status"] if isinstance(row, sqlite3.Row) else row[13],
                "created_at": row["created_at"] if isinstance(row, sqlite3.Row) else row[14],
                "assessment": _safe_saved_assessment(
                    row["assessment_json"] if isinstance(row, sqlite3.Row) else row[15],
                    row["detected_category"] if isinstance(row, sqlite3.Row) else row[3],
                ),
            })
        return reports
    finally:
        conn.close()


def fetch_report_by_id(report_id: int, user_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        if user_id is not None:
            if db_type == "mysql":
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports WHERE id = %s AND user_id = %s", (report_id, user_id))
            else:
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports WHERE id = ? AND user_id = ?", (report_id, user_id))
        else:
            if db_type == "mysql":
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports WHERE id = %s", (report_id,))
            else:
                cursor.execute("SELECT id, report_ref, complaint, detected_category, related_category, confidence, urgency, indicators, follow_up_answers, legal_guidance, evidence, next_steps, session_id, status, created_at, assessment_json FROM reports WHERE id = ?", (report_id,))
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row["id"] if isinstance(row, sqlite3.Row) else row[0],
            "report_ref": row["report_ref"] if isinstance(row, sqlite3.Row) else row[1],
            "complaint": row["complaint"] if isinstance(row, sqlite3.Row) else row[2],
            "detected_category": row["detected_category"] if isinstance(row, sqlite3.Row) else row[3],
            "related_category": row["related_category"] if isinstance(row, sqlite3.Row) else row[4],
            "confidence": row["confidence"] if isinstance(row, sqlite3.Row) else row[5],
            "urgency": row["urgency"] if isinstance(row, sqlite3.Row) else row[6],
            "indicators": safe_json_load(row["indicators"] if isinstance(row, sqlite3.Row) else row[7], []),
            "follow_up_answers": safe_json_load(row["follow_up_answers"] if isinstance(row, sqlite3.Row) else row[8], {}),
            "legal_guidance": _legal_guidance_for_category(row["detected_category"] if isinstance(row, sqlite3.Row) else row[3]),
            "evidence": safe_json_load(row["evidence"] if isinstance(row, sqlite3.Row) else row[10], []),
            "next_steps": safe_json_load(row["next_steps"] if isinstance(row, sqlite3.Row) else row[11], []),
            "session_id": row["session_id"] if isinstance(row, sqlite3.Row) else row[12],
            "status": row["status"] if isinstance(row, sqlite3.Row) else row[13],
            "created_at": row["created_at"] if isinstance(row, sqlite3.Row) else row[14],
            "assessment": _safe_saved_assessment(
                row["assessment_json"] if isinstance(row, sqlite3.Row) else row[15],
                row["detected_category"] if isinstance(row, sqlite3.Row) else row[3],
            ),
        }
    finally:
        conn.close()


@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = str(request.form.get("username", "")).strip()
        password = str(request.form.get("password", "")).strip()

        if APP_USERNAME and APP_PASSWORD and username == APP_USERNAME and password == APP_PASSWORD:
            session["logged_in"] = True
            session["username"] = username
            session["full_name"] = "Administrator"
            session["user_id"] = 0
            return redirect(url_for("dashboard"))

        user = get_user_by_username(username)
        if user and user.get("password_hash") and check_password_hash(user["password_hash"], password):
            session["logged_in"] = True
            session["username"] = user["username"]
            session["full_name"] = user.get("full_name") or user["username"]
            session["user_id"] = user.get("id", 0)
            return redirect(url_for("dashboard"))

        return render_template("login.html", error="Invalid username or password.")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name = str(request.form.get("full_name", "")).strip()
        username = str(request.form.get("username", "")).strip()
        password = str(request.form.get("password", "")).strip()
        confirm_password = str(request.form.get("confirm_password", "")).strip()

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match.")

        try:
            user = create_new_user(full_name, username, password)
        except ValueError as exc:
            return render_template("register.html", error=str(exc))

        session["logged_in"] = True
        session["username"] = user["username"]
        session["full_name"] = user["full_name"]
        session["user_id"] = user.get("id", 0)
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    reports = fetch_reports(user_id)
    recent_reports = reports[:5]
    stats = {
        "total_reports": len(reports),
        "reports_this_month": sum(1 for report in reports if report.get("created_at") and datetime.strptime(report["created_at"], "%Y-%m-%d %H:%M:%S").month == datetime.now().month),
        "high_confidence_cases": sum(1 for report in reports if int(report.get("confidence", 0) or 0) >= 80),
        "pending_assessments": max(0, 3 - len(reports)),
    }
    return render_template("dashboard.html", username=session.get("full_name") or session.get("username", "Admin"), stats=stats, recent_reports=recent_reports, recent_sessions=fetch_chat_sessions(user_id)[:5])


@app.route("/incident-report")
def incident_report_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("incident_report.html", username=session.get("full_name") or session.get("username", "Admin"))


@app.route("/my-reports")
def my_reports_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    reports = fetch_reports(session.get("user_id"))
    return render_template("my_reports.html", username=session.get("full_name") or session.get("username", "Admin"), reports=reports)


@app.route("/legal-guidance")
def legal_guidance_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    categories = build_legal_guidance_categories()
    return render_template("legal_guidance.html", username=session.get("full_name") or session.get("username", "Admin"), categories=categories)


@app.route("/safety-help")
def safety_help_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("safety_help.html", username=session.get("full_name") or session.get("username", "Admin"))


@app.route("/chat-history")
def chat_history_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    search_query = request.args.get("q", "").strip()[:200]
    sessions = fetch_chat_sessions(session.get("user_id"), search_query)
    return render_template(
        "chat_history.html",
        username=session.get("full_name") or session.get("username", "Admin"),
        sessions=sessions,
        search_query=search_query,
    )


@app.route("/profile")
def profile_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("profile.html", username=session.get("full_name") or session.get("username", "Admin"), user=session)


@app.route("/settings")
def settings_page():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("settings.html", username=session.get("full_name") or session.get("username", "Admin"))


def _chat_rate_limited(client_ip: str) -> bool:
    now = time.monotonic()
    recent = [stamp for stamp in CHAT_REQUEST_TIMES.get(client_ip, []) if now - stamp < 60]
    if len(recent) >= 30:
        CHAT_REQUEST_TIMES[client_ip] = recent
        return True
    recent.append(now)
    CHAT_REQUEST_TIMES[client_ip] = recent
    return False


def _contains_authentication_secret(message: str) -> bool:
    numeric_secret = re.search(
        r"\b(?:otp|one[- ]time password|pin|cvv|security code|authentication code)\b\s*(?::|=|is)?\s*\d{4,8}\b",
        message,
        flags=re.IGNORECASE,
    )
    written_password = re.search(
        r"\bpassword\b\s*(?::|=|is)\s*(?!compromised\b|stolen\b|changed\b|reset\b|unknown\b|forgotten\b|expired\b|hacked\b)[A-Za-z0-9@#$%&*!_-]{6,}",
        message,
        flags=re.IGNORECASE,
    )
    return numeric_secret is not None or written_password is not None


def _legal_guidance_for_category(category: str) -> Dict[str, Any]:
    guidance = LEGAL_GUIDANCE_MAP.get(category, {})
    return {
        "category": category,
        "general_legal_explanation": guidance.get(
            "general_legal_explanation",
            "No category-specific legal explanation is verified in the local legal dataset.",
        ),
        "relevant_indian_law": guidance.get(
            "relevant_indian_law",
            "No section-specific citation is available in the verified local legal dataset.",
        ),
        "potential_consequences": guidance.get("potential_consequences", []),
        "applicable_laws": [],
        "legal_provisions": [],
        "disclaimer": guidance.get(
            "disclaimer",
            "This is preliminary information, not a formal legal determination. Applicability depends on the facts and current law.",
        ),
    }


def _format_ai_analysis(analysis: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    category_map = {
        "Financial cyber fraud": "Financial Cyber Fraud",
        "Phishing": "Phishing",
        "Impersonation": "Online Impersonation",
        "Account takeover": "Unauthorized Account Access",
        "Unauthorized access": "Unauthorized Account Access",
        "Social media fraud": "Social Media Crime",
        "Cyber harassment": "Online Harassment",
        "Online shopping fraud": "Online Shopping Fraud",
        "Job and investment scams": "Job and Investment Scam",
        "Identity theft": "Identity Theft",
        "Privacy violations": "Data Theft / Data Exposure",
        "Extortion": "Cyber Extortion",
        "Malware or ransomware": "Malware / Malicious Software",
        "Other or uncertain": "Uncertain",
    }
    category = category_map[analysis["crime_type"]]
    evidence = analysis["evidence"]
    next_steps = analysis["next_steps"]
    if category in {"Financial Cyber Fraud", "UPI Fraud"}:
        urgent_action = "If money was lost, contact your bank/payment provider immediately and call India's official cybercrime helpline 1930 where applicable."
        if urgent_action not in next_steps:
            next_steps.insert(0, urgent_action)
    confidence = analysis["confidence"]
    confidence_label = "Low" if confidence < 40 else "Medium" if confidence < 70 else "High"
    question = analysis["follow_up_question"] if analysis["response_type"] == "follow_up" else ""
    verification_note = (
        "Verification needed: no specific Indian legal provision has been verified for this assessment. "
        "Consult a qualified legal professional or an authoritative current source."
    )
    legal_guidance = {
        "category": category,
        "general_legal_explanation": (
            "Potential legal topics for review: " + "; ".join(analysis["legal_topics"])
            if analysis["legal_topics"]
            else verification_note
        ),
        "relevant_indian_law": verification_note,
        "potential_consequences": [],
        "applicable_laws": [],
        "legal_provisions": [],
        "topics_for_review": analysis["legal_topics"],
        "verified_references": [],
        "verification_needed": True,
        "verification_note": verification_note,
        "disclaimer": "This is a preliminary AI assessment, not legal advice or an official legal determination.",
    }
    return {
        "type": analysis["response_type"],
        "response_type": analysis["response_type"],
        "language": analysis["language"],
        "category": category,
        "crime_type": analysis["crime_type"],
        "confidence": confidence,
        "confidence_label": f"AI estimate ({confidence_label} confidence)",
        "severity": analysis["severity"],
        "severity_explanation": analysis["severity_explanation"],
        "urgency": analysis["severity"].upper(),
        "summary": analysis["summary"],
        "response": analysis["summary"],
        "facts": analysis["facts"],
        "indicators": analysis["indicators"],
        "missing_information": analysis["missing_information"],
        "question": question,
        "follow_up_question": question,
        "options": [],
        "evidence": evidence,
        "evidence_to_preserve": evidence,
        "next_steps": next_steps,
        "recommended_actions": next_steps,
        "legal_guidance": legal_guidance,
        "disclaimer": "This is a preliminary AI assessment, not legal advice or an official legal determination.",
        "session_id": session_id,
    }


def _claim_chat_analysis_retry(session_id: str, user_id: int) -> bool:
    conn, db_type = get_db_connection()
    try:
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "mysql" else "?"
        cursor.execute(
            f"UPDATE chat_sessions SET status = {placeholder} WHERE session_id = {placeholder} "
            f"AND user_id = {placeholder} AND status = {placeholder}",
            ("Analysis pending", session_id, user_id, "Analysis unavailable"),
        )
        claimed = cursor.rowcount == 1
        conn.commit()
        return claimed
    finally:
        conn.close()


def _run_chat_analysis(
    session_id: str,
    message: str,
    history: List[Dict[str, str]],
    complaint: str,
    language: str,
):
    try:
        analysis = analyze_complaint(message, history)
    except (AnalysisConfigurationError, AnalysisServiceError) as exc:
        response_message = str(exc)
        if "complaint was saved" not in response_message.lower():
            response_message = f"{response_message} Your complaint was saved, but it was not assessed."
        failure_kind = getattr(exc, "failure_kind", "unavailable")
        update_chat_session_analysis(
            session_id,
            "Unassessed",
            0,
            "Analysis unavailable",
            language,
            {},
        )
        return jsonify({
            "type": "error",
            "error": response_message,
            "response": response_message,
            "failure_kind": failure_kind,
            "provider_error_code": getattr(exc, "code", None),
            "retry_available": failure_kind in {
                "provider_overloaded",
                "provider_deadline",
                "provider_temporary",
                "rate_limit",
                "timeout",
                "provider_unavailable",
                "invalid_response",
                "incomplete_response",
            },
            "session_id": session_id,
            "complaint": complaint,
        }), 503
    except Exception as exc:
        logger.error("Unexpected chat analysis failure: error_type=%s", type(exc).__name__)
        response_message = (
            "The analysis service encountered an unexpected error. Your complaint was saved, "
            "but it was not assessed."
        )
        update_chat_session_analysis(
            session_id,
            "Unassessed",
            0,
            "Analysis unavailable",
            language,
            {},
        )
        return jsonify({
            "type": "error",
            "error": response_message,
            "response": response_message,
            "failure_kind": "provider_error",
            "retry_available": False,
            "session_id": session_id,
            "complaint": complaint,
        }), 503

    result = _format_ai_analysis(analysis, session_id)
    result["complaint"] = complaint
    save_chat_message(session_id, "assistant", result["question"] or result["response"])
    update_chat_session_analysis(
        session_id,
        result["category"],
        analysis["confidence"],
        "Follow-up" if analysis["response_type"] == "follow_up" else "Complete",
        analysis["language"],
        result,
    )
    return jsonify(result), 200


@app.route("/api/health", methods=["GET"])
def api_health():
    try:
        sdk_version = package_version("google-genai")
    except PackageNotFoundError:
        sdk_version = "unavailable"
    return jsonify({
        "status": "ok",
        "ai_configured": bool(os.getenv("GEMINI_API_KEY", "").strip()),
        "gemini_model": get_configured_model(),
        "google_genai_version": sdk_version,
    })


@app.route("/chat", methods=["POST"])
@app.route("/api/chat", methods=["POST"])
def chat():
    if not session.get("logged_in"):
        return jsonify({"type": "error", "error": "Authentication required.", "response": "Please sign in to use the assistant."}), 401
    if _chat_rate_limited(request.remote_addr or "unknown"):
        return jsonify({"type": "error", "error": "Too many requests.", "response": "Please wait a moment before sending another message."}), 429

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"type": "error", "error": "Invalid request.", "response": "Please send a valid JSON request."}), 400
    message = payload.get("message")
    if not isinstance(message, str) or not message.strip():
        return jsonify({"type": "error", "error": "Message is required.", "response": "Please enter a complaint before submitting."}), 400
    message = message.strip()
    if len(message) > 2500:
        return jsonify({"type": "error", "error": "Message is too long.", "response": "The complaint is too long. Please keep it under 2500 characters."}), 400
    if _contains_authentication_secret(message):
        return jsonify({
            "type": "error",
            "error": "Authentication secrets are not accepted.",
            "response": "Please remove any password, OTP, PIN, CVV, or security code before sending. Contact your bank or service provider if you have already shared one.",
        }), 400

    requested_session_id = payload.get("session_id")
    if isinstance(requested_session_id, str):
        requested_session_id = requested_session_id.strip() or None
    if requested_session_id is not None and (
        not isinstance(requested_session_id, str)
        or len(requested_session_id) > 80
        or not re.fullmatch(r"[A-Za-z0-9_-]+", requested_session_id)
    ):
        return jsonify({
            "type": "error",
            "error": "Invalid session identifier.",
            "response": "Please start a new complaint session."
        }), 400

    session_id = requested_session_id or generate_session_id()
    user_id = int(session.get("user_id", 0) or 0)
    owner_id = get_chat_session_owner(session_id)
    if owner_id is not None and owner_id != user_id:
        return jsonify({"type": "error", "error": "Chat session not found.", "response": "That chat session is unavailable."}), 404

    existing = fetch_chat_session_by_id(session_id, user_id)
    messages = existing.get("messages", [])
    last_user_message_is_duplicate = (
        bool(messages)
        and messages[-1]["role"] == "user"
        and messages[-1]["message"] == message
    )
    last_completed_turn_is_duplicate = (
        len(messages) >= 2
        and messages[-1]["role"] == "assistant"
        and messages[-2]["role"] == "user"
        and messages[-2]["message"] == message
    )
    if last_user_message_is_duplicate and existing.get("status") == "Analysis pending":
        return jsonify({
            "type": "error",
            "error": "This message is already being analyzed.",
            "response": "Your complaint is already being analyzed. Please wait for the current request.",
            "session_id": session_id,
        }), 409
    if last_completed_turn_is_duplicate and existing.get("status") in {"Complete", "Follow-up"}:
        saved_analysis = existing.get("analysis", {})
        if isinstance(saved_analysis, dict) and saved_analysis.get("type") in {"final", "follow_up", "question"}:
            return jsonify(saved_analysis), 200

    history = [
        {"role": turn["role"], "content": turn["message"]}
        for turn in messages[-10:]
        if turn["role"] in {"user", "assistant"}
    ]

    is_new_session = owner_id is None
    is_retry_submission = (
        not is_new_session
        and existing.get("status") == "Analysis unavailable"
        and last_user_message_is_duplicate
    )
    if is_new_session:
        detected = detect_language(message)
        create_chat_session(
            session_id,
            message,
            detected["language"],
            "Unassessed",
            0,
            user_id=user_id,
        )
    if is_retry_submission:
        history = history[:-1]
    else:
        save_chat_message(session_id, "user", message)

    language = existing.get("detected_language") or detect_language(message)["language"]
    update_chat_session_analysis(
        session_id,
        existing.get("detected_category") or "Unassessed",
        int(existing.get("confidence") or 0),
        "Analysis pending",
        language,
        {},
    )
    return _run_chat_analysis(
        session_id,
        message,
        history,
        existing.get("complaint") or message,
        language,
    )


@app.route("/api/chat/retry", methods=["POST"])
def retry_chat_analysis():
    if not session.get("logged_in"):
        return jsonify({"type": "error", "error": "Authentication required.", "response": "Please sign in to use the assistant."}), 401
    if _chat_rate_limited(request.remote_addr or "unknown"):
        return jsonify({"type": "error", "error": "Too many requests.", "response": "Please wait a moment before retrying."}), 429

    payload = request.get_json(silent=True)
    session_id = payload.get("session_id") if isinstance(payload, dict) else None
    if (
        not isinstance(session_id, str)
        or len(session_id) > 80
        or not re.fullmatch(r"[A-Za-z0-9_-]+", session_id)
    ):
        return jsonify({"type": "error", "error": "Invalid session identifier.", "response": "Please select a saved complaint to retry."}), 400

    user_id = int(session.get("user_id", 0) or 0)
    if get_chat_session_owner(session_id) != user_id:
        return jsonify({"type": "error", "error": "Chat session not found.", "response": "That chat session is unavailable."}), 404
    existing = fetch_chat_session_by_id(session_id, user_id)
    if existing.get("status") != "Analysis unavailable":
        return jsonify({
            "type": "error",
            "error": "This complaint is not awaiting analysis retry.",
            "response": "Only a saved complaint with a failed analysis can be retried.",
            "session_id": session_id,
        }), 409

    messages = existing.get("messages", [])
    last_user_index = next(
        (index for index in range(len(messages) - 1, -1, -1) if messages[index]["role"] == "user"),
        None,
    )
    if last_user_index is None:
        return jsonify({
            "type": "error",
            "error": "No saved complaint message is available to retry.",
            "response": "The saved complaint has no message to analyze.",
            "session_id": session_id,
        }), 409
    if not _claim_chat_analysis_retry(session_id, user_id):
        return jsonify({
            "type": "error",
            "error": "Analysis retry is already in progress.",
            "response": "This complaint is already being analyzed. Please wait.",
            "session_id": session_id,
        }), 409

    message = messages[last_user_index]["message"]
    history = [
        {"role": item["role"], "content": item["message"]}
        for item in messages[:last_user_index]
        if item["role"] in {"user", "assistant"}
    ][-10:]
    language = existing.get("detected_language") or detect_language(message)["language"]
    return _run_chat_analysis(
        session_id,
        message,
        history,
        existing.get("complaint") or message,
        language,
    )


@app.route("/reports", methods=["POST"])
def save_report_route():
    if not session.get("logged_in"):
        return jsonify({"error": "Authentication required."}), 401
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "A valid JSON report is required."}), 400
    session_id = payload.get("session_id")
    if (
        not isinstance(session_id, str)
        or len(session_id) > 80
        or not re.fullmatch(r"[A-Za-z0-9_-]+", session_id)
    ):
        return jsonify({"error": "A valid completed chat session is required."}), 400
    user_id = int(session.get("user_id", 0) or 0)
    if get_chat_session_owner(session_id) != user_id:
        return jsonify({"error": "Chat session not found."}), 404
    chat_session = fetch_chat_session_by_id(session_id, user_id)
    assessment = chat_session.get("analysis", {})
    if chat_session.get("status") != "Complete" or assessment.get("type") != "final":
        return jsonify({"error": "Complete the assessment before saving a report."}), 409

    complaint = chat_session.get("complaint", "")
    if not isinstance(complaint, str) or not complaint.strip():
        return jsonify({"error": "The completed chat has no complaint to save."}), 400
    if _contains_authentication_secret(complaint):
        return jsonify({"error": "Remove authentication secrets before saving this report."}), 400
    answers = payload.get("answers", {})
    if not isinstance(answers, dict) or len(answers) > 12 or any(
        not isinstance(question, str)
        or not isinstance(answer, str)
        or len(question) > 500
        or len(answer) > 2500
        for question, answer in answers.items()
    ):
        return jsonify({"error": "Invalid follow-up answers."}), 400

    messages = chat_session.get("messages", [])
    persisted_answers = {}
    for index, item in enumerate(messages[:-1]):
        if (
            item["role"] == "assistant"
            and item["message"].rstrip().endswith(("?", "？"))
            and messages[index + 1]["role"] == "user"
        ):
            persisted_answers[item["message"]] = messages[index + 1]["message"]
    safe_assessment = dict(assessment)
    safe_assessment["legal_guidance"] = _legal_guidance_for_category(
        assessment.get("category", "Uncertain")
    )
    report_payload = {
        "complaint": complaint,
        "category": assessment.get("category", "Uncertain"),
        "related_category": assessment.get("related_category", ""),
        "confidence": assessment.get("confidence", 0),
        "urgency": assessment.get("urgency", "LOW"),
        "indicators": assessment.get("indicators", []),
        "answers": persisted_answers,
        "legal_guidance": safe_assessment["legal_guidance"],
        "evidence": assessment.get("evidence", []),
        "next_steps": assessment.get("next_steps", []),
        "assessment": safe_assessment,
        "session_id": session_id,
        "status": "Saved",
        "user_id": user_id,
    }

    existing_report_id = find_report_for_assessment(session_id, user_id, safe_assessment)
    if existing_report_id is not None:
        saved_report = fetch_report_by_id(existing_report_id, user_id)
        return jsonify({
            "success": True,
            "report_id": existing_report_id,
            "report_ref": saved_report.get("report_ref") if saved_report else None,
        }), 200

    report_id = save_report(report_payload)
    saved_report = fetch_report_by_id(report_id, session.get("user_id"))
    return jsonify({"success": True, "report_id": report_id, "report_ref": saved_report.get("report_ref") if saved_report else None}), 201


@app.route("/api/reports", methods=["POST"])
def api_save_report_route():
    return save_report_route()


@app.route("/reports", methods=["GET"])
def list_reports_route():
    if not session.get("logged_in"):
        return jsonify({"error": "Authentication required."}), 401
    return jsonify({"reports": fetch_reports(session.get("user_id"))})


@app.route("/api/reports", methods=["GET"])
def api_list_reports_route():
    return list_reports_route()


@app.route("/reports/<int:report_id>", methods=["GET"])
def report_detail_route(report_id: int):
    if not session.get("logged_in"):
        return jsonify({"error": "Authentication required."}), 401
    report = fetch_report_by_id(report_id, session.get("user_id"))
    if not report:
        return jsonify({"error": "Report not found."}), 404
    return jsonify(report)


@app.route("/report/<int:report_id>")
def report_page(report_id: int):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    report = fetch_report_by_id(report_id, session.get("user_id"))
    if not report:
        return render_template("report.html", report=None), 404
    return render_template("report.html", report=report, username=session.get("full_name") or session.get("username", "Admin"))


@app.route("/report/<int:report_id>/download")
def download_report(report_id: int):
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    report = fetch_report_by_id(report_id, session.get("user_id"))
    if not report:
        return jsonify({"error": "Report not found."}), 404
    response = make_response(render_template("report.html", report=report, username=session.get("full_name") or session.get("username", "Admin")))
    response.headers["Content-Disposition"] = f"attachment; filename={report.get('report_ref') or 'cyber-incident-report'}.html"
    return response


@app.route("/api/reports/<int:report_id>", methods=["GET"])
def api_report_detail_route(report_id: int):
    return report_detail_route(report_id)


@app.route("/api/chat-history", methods=["GET"])
def api_chat_history_route():
    if not session.get("logged_in"):
        return jsonify({"error": "Authentication required."}), 401
    search_query = request.args.get("q", "").strip()[:200]
    return jsonify({"sessions": fetch_chat_sessions(session.get("user_id"), search_query)})


@app.route("/api/chat-history/<session_id>", methods=["GET"])
def api_chat_history_detail_route(session_id: str):
    if not session.get("logged_in"):
        return jsonify({"error": "Authentication required."}), 401
    saved_session = fetch_chat_session_by_id(session_id, session.get("user_id"))
    if not saved_session.get("session_id"):
        return jsonify({"error": "Chat session not found."}), 404
    return jsonify(saved_session)


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(500)
def server_error(_):
    return jsonify({"error": "I couldn't process that message right now. Please try again."}), 500


initialize_database()

if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG", "false").lower() == "true", host="127.0.0.1", port=5000)
