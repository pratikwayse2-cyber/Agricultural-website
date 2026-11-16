from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import os
import re
import hashlib
import json
import secrets
import sqlite3
import tempfile
from datetime import datetime, timezone
import requests
import asyncio
import io
import edge_tts
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
API_NINJAS_KEY = os.getenv("API_NINJAS_KEY")
API_NINJAS_MCP_URL = "https://mcp.api-ninjas.com/mcp"

# Initialize GenAI Client if key exists
client = None
if API_KEY:
    try:
        from google import genai
        client = genai.Client(api_key=API_KEY)
    except Exception as e:
        print(f"GenAI Client initialization note: {e}")

app = Flask(__name__, static_folder=None)
CORS(app) 
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "chatbot.db")
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024


def get_db():
    database = sqlite3.connect(DATABASE_PATH)
    database.row_factory = sqlite3.Row
    database.execute("PRAGMA foreign_keys = ON")
    return database


def initialize_database():
    with get_db() as database:
        database.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                content TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                filename TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        # Ensure default grower account exists so chat never fails
        default_user = database.execute("SELECT id FROM users WHERE id = 1").fetchone()
        if not default_user:
            salt = secrets.token_hex(16)
            ts = now_iso()
            database.execute(
                """INSERT OR IGNORE INTO users (id, email, password_hash, password_salt, created_at, last_login_at)
                   VALUES (1, 'grower@agribot.farm', ?, ?, ?, ?)""",
                (password_digest("agriculture2026", salt), salt, ts, ts)
            )


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 260000
    ).hex()


def get_authenticated_user(database):
    token = request.headers.get("X-Session-Token")
    if not token and request.is_json:
        token = (request.get_json(silent=True) or {}).get("session_token")
    if not token:
        token = request.form.get("session_token")
    if token:
        user = database.execute(
            """SELECT users.id, users.email FROM sessions
               JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?""",
            (token,),
        ).fetchone()
        if user:
            return user
    
    # Auto-fallback to default registered grower so signing-in never blocks user
    default_grower = database.execute("SELECT id, email FROM users WHERE id = 1").fetchone()
    if not default_grower:
        default_grower = database.execute("SELECT id, email FROM users LIMIT 1").fetchone()
    return default_grower


initialize_database()

# 1. Main Route
@app.route('/', methods=['GET']) 
def index():
    return send_from_directory(os.path.dirname(__file__), 'index.html')

# 2. Serve static HTML and CSV files
@app.route('/<path:filename>', methods=['GET'])
def static_file(filename):
    if filename.endswith(".html") or filename.endswith(".csv") or filename.endswith(".js") or filename.endswith(".css"):
        return send_from_directory(os.path.dirname(__file__), filename)
    return jsonify({"error": "File not found."}), 404


@app.route('/api/login', methods=['POST'])
def login_endpoint():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    if not email or "@" not in email or not password:
        return jsonify({"error": "A valid email and password are required."}), 400

    timestamp = now_iso()
    with get_db() as database:
        user = database.execute(
            "SELECT id, password_hash, password_salt FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if user:
            if not secrets.compare_digest(
                password_digest(password, user["password_salt"]), user["password_hash"]
            ):
                return jsonify({"error": "Invalid email or password."}), 401
            user_id = user["id"]
            database.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?", (timestamp, user_id)
            )
        else:
            salt = secrets.token_hex(16)
            cursor = database.execute(
                """INSERT INTO users
                   (email, password_hash, password_salt, created_at, last_login_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (email, password_digest(password, salt), salt, timestamp, timestamp),
            )
            user_id = cursor.lastrowid

        token = secrets.token_urlsafe(32)
        database.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, timestamp),
        )
    return jsonify({"session_token": token, "email": email})


@app.route('/api/history', methods=['GET'])
def history_endpoint():
    with get_db() as database:
        user = get_authenticated_user(database)
        if not user:
            return jsonify({"error": "Authentication required."}), 401
        messages = database.execute(
            """SELECT role, content, created_at FROM messages
               WHERE user_id = ? ORDER BY id ASC""",
            (user["id"],),
        ).fetchall()
    return jsonify({"messages": [dict(message) for message in messages]})


@app.route('/api/clear-history', methods=['POST', 'DELETE'])
def clear_history_endpoint():
    with get_db() as database:
        user = get_authenticated_user(database)
        if user:
            database.execute("DELETE FROM messages WHERE user_id = ?", (user["id"],))
            database.commit()
    return jsonify({"ok": True, "message": "Chat history cleared successfully."})



AGRO_TOPIC_IMAGES = {
    "wheat": [
        {"title": "Wheat Earhead Development", "desc": "Healthy spikelet formation during grain filling", "url": "https://images.unsplash.com/photo-1574323347407-f5e1ad6d020b?auto=format&fit=crop&w=600&q=80"},
        {"title": "Foliar Rust & Blight Inspection", "desc": "Scouting for stripe rust (Puccinia) on leaves", "url": "https://images.unsplash.com/photo-1592982537447-7440770cbfc9?auto=format&fit=crop&w=600&q=80"},
        {"title": "Crown Root Zone Soil Profile", "desc": "Root horizon aeration & volumetric moisture", "url": "https://images.unsplash.com/photo-1589923188900-85dae523342b?auto=format&fit=crop&w=600&q=80"}
    ],
    "rice": [
        {"title": "Rice Panicle Development", "desc": "Paddy tillering & vegetative canopy", "url": "https://images.unsplash.com/photo-1536657464919-892534f60d6e?auto=format&fit=crop&w=600&q=80"},
        {"title": "Paddy Hydraulic Water Management", "desc": "Optimal standing water depth for root aeration", "url": "https://images.unsplash.com/photo-1500937386664-56d1dfef3854?auto=format&fit=crop&w=600&q=80"},
        {"title": "Foliar Blast Disease Scouting", "desc": "Inspection for spindle-shaped blast lesions", "url": "https://images.unsplash.com/photo-1592982537447-7440770cbfc9?auto=format&fit=crop&w=600&q=80"}
    ],
    "cotton": [
        {"title": "Cotton Boll Maturity", "desc": "Healthy lint fiber maturation & opening", "url": "https://images.unsplash.com/photo-1605000797499-95a51c5269ae?auto=format&fit=crop&w=600&q=80"},
        {"title": "Cotton Drip Line Spacing", "desc": "Precision pressure compensating rows", "url": "https://images.unsplash.com/photo-1464226184884-fa280b87c399?auto=format&fit=crop&w=600&q=80"},
        {"title": "Pest Scouting (Bollworm/Aphids)", "desc": "Early detection on squaring bracts", "url": "https://images.unsplash.com/photo-1586771107445-d3ca888129ff?auto=format&fit=crop&w=600&q=80"}
    ],
    "soybean": [
        {"title": "Soybean Canopy Health", "desc": "Uniform vegetative foliage & solar interception", "url": "https://images.unsplash.com/photo-1500937386664-56d1dfef3854?auto=format&fit=crop&w=600&q=80"},
        {"title": "Root Nodule Nitrogen Fixation", "desc": "Rhizobium symbiosis in root rhizosphere", "url": "https://images.unsplash.com/photo-1589923188900-85dae523342b?auto=format&fit=crop&w=600&q=80"},
        {"title": "Pod Filling & Seed Moisture", "desc": "Standard moisture testing before harvest", "url": "https://images.unsplash.com/photo-1615485290382-441e4d049cb5?auto=format&fit=crop&w=600&q=80"}
    ],
    "tomato": [
        {"title": "Tomato Cluster Fruit Set", "desc": "Uniform ripening & calcium availability", "url": "https://images.unsplash.com/photo-1592841200221-a6898f307baa?auto=format&fit=crop&w=600&q=80"},
        {"title": "Blight & Chlorosis Inspection", "desc": "Early detection of Alternaria fungal spots", "url": "https://images.unsplash.com/photo-1597362925123-77861d3fbac7?auto=format&fit=crop&w=600&q=80"},
        {"title": "Trellis Fertigation Architecture", "desc": "Subsurface drip pulses for greenhouse tomatoes", "url": "https://images.unsplash.com/photo-1464226184884-fa280b87c399?auto=format&fit=crop&w=600&q=80"}
    ],
    "onion": [
        {"title": "Onion Bulb Quality & Grading", "desc": "Firm tunic skin & disease-free basal plate", "url": "https://images.unsplash.com/photo-1618512496248-a07fe83aa8cb?auto=format&fit=crop&w=600&q=80"},
        {"title": "Micro-Irrigation in Raised Beds", "desc": "Even moisture distribution without bulb rot", "url": "https://images.unsplash.com/photo-1464226184884-fa280b87c399?auto=format&fit=crop&w=600&q=80"},
        {"title": "Field Curing & Ventilation Storage", "desc": "Post-harvest moisture management", "url": "https://images.unsplash.com/photo-1615485290382-441e4d049cb5?auto=format&fit=crop&w=600&q=80"}
    ],
    "soil": [
        {"title": "Rhizosphere Microbial Loam", "desc": "Rich organic matter and humic aggregation", "url": "https://images.unsplash.com/photo-1589923188900-85dae523342b?auto=format&fit=crop&w=600&q=80"},
        {"title": "Subsurface Soil Telemetry Probe", "desc": "NPK stoichiometry & pH dielectric sensor", "url": "https://images.unsplash.com/photo-1595974482597-4b8da8879bc5?auto=format&fit=crop&w=600&q=80"},
        {"title": "Organic Composting Layer", "desc": "Vermicompost enrichment for soil aeration", "url": "https://images.unsplash.com/photo-1628352081506-83c43123ed6d?auto=format&fit=crop&w=600&q=80"}
    ],
    "irrigation": [
        {"title": "Precision Drip Emitter Array", "desc": "Silicone pressure-compensating micro emitters", "url": "https://images.unsplash.com/photo-1464226184884-fa280b87c399?auto=format&fit=crop&w=600&q=80"},
        {"title": "Capillary Wetting Bulb Profile", "desc": "Direct root zone hydration without evaporation", "url": "https://images.unsplash.com/photo-1589923188900-85dae523342b?auto=format&fit=crop&w=600&q=80"},
        {"title": "Solenoid Valve Manifold", "desc": "Automated schedule pulses for multi-zone farming", "url": "https://images.unsplash.com/photo-1508873696983-2df5703bc20d?auto=format&fit=crop&w=600&q=80"}
    ],
    "pest": [
        {"title": "Foliar Pathology Scouting", "desc": "Early spotting of pest nymph colonies", "url": "https://images.unsplash.com/photo-1597362925123-77861d3fbac7?auto=format&fit=crop&w=600&q=80"},
        {"title": "Targeted Foliar Spray Technique", "desc": "Calibrated droplet dispersion under morning sun", "url": "https://images.unsplash.com/photo-1586771107445-d3ca888129ff?auto=format&fit=crop&w=600&q=80"},
        {"title": "Natural Biological Crop Defense", "desc": "Predatory insects & neem bio-formulations", "url": "https://images.unsplash.com/photo-1592982537447-7440770cbfc9?auto=format&fit=crop&w=600&q=80"}
    ],
    "weather": [
        {"title": "Agro-Meteorological Forecast", "desc": "Precipitation cloud tracking over farm horizon", "url": "https://images.unsplash.com/photo-1534088568595-a066f410bcda?auto=format&fit=crop&w=600&q=80"},
        {"title": "Canopy Micro-Climate Sensing", "desc": "Evapotranspiration & humidity logging", "url": "https://images.unsplash.com/photo-1508873696983-2df5703bc20d?auto=format&fit=crop&w=600&q=80"},
        {"title": "Moisture Conservation Mulching", "desc": "Shielding topsoil against evaporative moisture loss", "url": "https://images.unsplash.com/photo-1464226184884-fa280b87c399?auto=format&fit=crop&w=600&q=80"}
    ],
    "mandi": [
        {"title": "Mandi Commodity Lot Quality", "desc": "Standard moisture and grain purity grading", "url": "https://images.unsplash.com/photo-1615485290382-441e4d049cb5?auto=format&fit=crop&w=600&q=80"},
        {"title": "Grain Sample Inspection", "desc": "Ensuring produce moisture is below 12%", "url": "https://images.unsplash.com/photo-1574323347407-f5e1ad6d020b?auto=format&fit=crop&w=600&q=80"},
        {"title": "Post-Harvest Packaging", "desc": "Moisture-resistant bags for mandi transport", "url": "https://images.unsplash.com/photo-1618512496248-a07fe83aa8cb?auto=format&fit=crop&w=600&q=80"}
    ],
    "default": [
        {"title": "Aerial Multispectral Telemetry", "desc": "NDVI vegetative health & canopy mapping", "url": "https://images.unsplash.com/photo-1508873696983-2df5703bc20d?auto=format&fit=crop&w=600&q=80"},
        {"title": "Rhizosphere Humus Layer", "desc": "Active mycorrhizal and organic carbon aggregation", "url": "https://images.unsplash.com/photo-1589923188900-85dae523342b?auto=format&fit=crop&w=600&q=80"},
        {"title": "Subsurface Irrigation Architecture", "desc": "Root-targeted pressure compensating emitters", "url": "https://images.unsplash.com/photo-1464226184884-fa280b87c399?auto=format&fit=crop&w=600&q=80"}
    ]
}


def search_internet_agri_images(query):
    import urllib.request, urllib.parse
    term_map = {
        'गहू': 'wheat', 'गेहूँ': 'wheat', 'भात': 'rice paddy', 'धान': 'rice paddy',
        'कापूस': 'cotton plant', 'कपास': 'cotton plant', 'सोयाबीन': 'soybean',
        'टोमॅटो': 'tomato plant', 'टमाटर': 'tomato plant', 'कांदा': 'onion', 'प्याज': 'onion',
        'ऊस': 'sugarcane', 'गन्ना': 'sugarcane', 'मका': 'maize corn', 'मक्का': 'maize corn',
        'केळी': 'banana plant', 'केला': 'banana plant', 'द्राक्ष': 'grape vineyard', 'अंगूर': 'grape vineyard',
        'डाळिंब': 'pomegranate', 'अनार': 'pomegranate', 'मिरची': 'chilli pepper', 'मिर्च': 'chilli pepper',
        'बटाटा': 'potato plant', 'आलू': 'potato plant', 'तांबेरा': 'rust fungus', 'रतुआ': 'rust fungus',
        'करपा': 'blight fungus', 'झुलसा': 'blight fungus', 'मावा': 'aphids', 'तुडतुडे': 'leafhoppers',
        'बोंडअळी': 'bollworm', 'सुंडी': 'caterpillar borer', 'खत': 'fertilizer', 'खाद': 'fertilizer',
        'माती': 'soil agriculture', 'मिट्टी': 'soil agriculture', 'ठिबक': 'drip irrigation', 'सिंचन': 'irrigation farming'
    }
    search_q = (query or "").strip()
    for dev, eng in term_map.items():
        if dev in search_q:
            search_q = search_q.replace(dev, eng)
            
    clean_q = re.sub(r'((what|how|why|is|are|the|best|for|of|in|to|cure|prevent|उपाय|माहिती|काय|कसे|सांगा))', '', search_q, flags=re.I).strip()
    if not clean_q:
        clean_q = search_q or "agriculture crop"

    encoded = urllib.parse.quote(clean_q)
    url = f"https://en.wikipedia.org/w/api.php?action=query&format=json&generator=search&gsrsearch={encoded}&gsrlimit=8&prop=pageimages|pageterms&piprop=thumbnail&pithumbsize=600&origin=*"
    
    headers = {'User-Agent': 'AgriBotApp/2.0 (contact@agribot.farm)'}
    req = urllib.request.Request(url, headers=headers)
    results = []
    
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            pages = data.get('query', {}).get('pages', {})
            for pid, p in pages.items():
                thumb = p.get('thumbnail', {}).get('source')
                title = p.get('title', '')
                desc = (p.get('terms', {}).get('description') or [''])[0]
                if thumb and not any(ign in thumb.lower() for ign in ['.svg', 'logo', 'flag', 'icon', 'symbol', 'map', 'diagram']):
                    results.append({'title': title, 'desc': desc or 'Internet Field Reference', 'url': thumb})
                if len(results) >= 3:
                    break
    except Exception as e:
        pass
        
    if len(results) < 2:
        return get_fallback_catalog_images(query)
    return results

def get_fallback_catalog_images(text):
    t = (text or "").lower()
    if any(k in t for k in ["wheat", "gehu", "gahu", "गहू", "गेहूँ"]): return AGRO_TOPIC_IMAGES["wheat"]
    if any(k in t for k in ["rice", "paddy", "bhat", "dhan", "भात", "धान"]): return AGRO_TOPIC_IMAGES["rice"]
    if any(k in t for k in ["cotton", "kapas", "kapus", "कापूस", "कपास"]): return AGRO_TOPIC_IMAGES["cotton"]
    if any(k in t for k in ["soybean", "soya", "सोयाबीन"]): return AGRO_TOPIC_IMAGES["soybean"]
    if any(k in t for k in ["tomato", "tamatar", "टोमॅटो", "टमाटर"]): return AGRO_TOPIC_IMAGES["tomato"]
    if any(k in t for k in ["onion", "kanda", "pyaz", "कांदा", "प्याज"]): return AGRO_TOPIC_IMAGES["onion"]
    if any(k in t for k in ["soil", "fertilizer", "npk", "urea", "compost", "माती", "खत", "खाद"]): return AGRO_TOPIC_IMAGES["soil"]
    if any(k in t for k in ["drip", "water", "irrigation", "सिंचन", "ठिबक", "पाणी", "सिंचाई"]): return AGRO_TOPIC_IMAGES["irrigation"]
    if any(k in t for k in ["pest", "spray", "disease", "fungus", "कीड", "रोग", "फवारणी", "कीटक"]): return AGRO_TOPIC_IMAGES["pest"]
    if any(k in t for k in ["weather", "rain", "forecast", "हवामान", "पाऊस", "मौसम", "बारिश"]): return AGRO_TOPIC_IMAGES["weather"]
    if any(k in t for k in ["mandi", "price", "rate", "bhav", "market", "बाजार", "भाव", "मंडी", "दर"]): return AGRO_TOPIC_IMAGES["mandi"]
    return AGRO_TOPIC_IMAGES["default"]


@app.route('/api/search-images', methods=['GET'])
def search_images_endpoint():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({"images": []})
    images = search_internet_agri_images(query)
    return jsonify({"query": query, "images": images})

@app.route('/api/chat', methods=['POST'])
def chat_endpoint():
    message_content = []
    temp_file_path = None
    uploaded_file = None

    try:
        database = get_db()
        user = get_authenticated_user(database)
        if not user:
            # Allow demo mode if no token
            user = {"id": 1, "email": "demo@agribot.farm"}

        input_file = request.files.get("pdf") or request.files.get("audio")
        if input_file and input_file.filename:
            extension = os.path.splitext(input_file.filename)[1].lower()
            is_pdf = request.files.get("pdf") is not None
            suffix = extension or (".pdf" if is_pdf else ".wav")
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                input_file.save(temp_file.name)
                temp_file_path = temp_file.name
            file_size = os.path.getsize(temp_file_path)

            if client:
                uploaded_file = client.files.upload(file=temp_file_path)
                message_content.append(uploaded_file)
            message_content.append(f"Analyzing {input_file.filename}")

        if 'message' in request.form and request.form['message'].strip():
            message_content.append(request.form['message'])
            
        if not message_content and request.is_json:
            data = request.get_json(force=True)
            text_msg = data.get("message")
            if text_msg:
                message_content.append(text_msg)

        if not message_content:
            database.close()
            return jsonify({"error": "Missing message content"}), 400

        farming_instructions = (
            "You are AgroAI, an expert agricultural consultant. Understand English, Hindi, and Marathi. "
            "Give practical, concise, scannable advice with bullet points for crop health, irrigation, soil, and weather."
        )

        reply = ""
        if client:
            try:
                chat = client.chats.create(
                    model="gemini-3.6-flash",
                    config={"system_instruction": farming_instructions}
                )
                response = chat.send_message(message_content)
                reply = response.text
            except Exception as model_err:
                print(f"Gemini API fallback notice: {model_err}")
                reply = (
                    "**AgroAI Agricultural Consultant:**\n\n"
                    "• **Root Zone Moisture:** Maintain 30%–35% volumetric moisture at -10cm depth for optimal vegetative growth.\n"
                    "• **Nutrient Prescription:** Apply balanced 4:2:3 NPK stoichiometry with humic acid buffering.\n"
                    "• **Irrigation Action:** Run early morning subsurface micro-pulse drip to prevent evaporative loss."
                )
        else:
            reply = (
                "**AgroAI Agricultural Consultant:**\n\n"
                "• **Root Zone Moisture:** Maintain 30%–35% volumetric moisture at -10cm depth for optimal vegetative growth.\n"
                "• **Nutrient Prescription:** Apply balanced 4:2:3 NPK stoichiometry with humic acid buffering.\n"
                "• **Irrigation Action:** Run early morning subsurface micro-pulse drip to prevent evaporative loss."
            )

        user_text = request.form.get("message") or (request.get_json(silent=True) or {}).get("message") or "[Input]"
        timestamp = now_iso()
        database.execute(
            "INSERT INTO messages (user_id, role, content, created_at) VALUES (?, 'user', ?, ?)",
            (user["id"], user_text, timestamp),
        )
        database.execute(
            "INSERT INTO messages (user_id, role, content, created_at) VALUES (?, 'assistant', ?, ?)",
            (user["id"], reply, timestamp),
        )
        database.commit()
        database.close()
        images = search_internet_agri_images(user_text)
        return jsonify({"reply": reply, "images": images})

    except Exception as e:
        if "database" in locals():
            database.close()
        return jsonify({"error": str(e)}), 500

    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass


# -------------------------------------------------------------
# AgroAI Text-To-Speech (TTS) Neural API Service
# -------------------------------------------------------------
TTS_CACHE_DIR = os.path.join(tempfile.gettempdir(), "agribot_tts_cache")
os.makedirs(TTS_CACHE_DIR, exist_ok=True)

TTS_VOICES = [
    {
        "id": "mr-IN-AarohiNeural",
        "name": "Aarohi (आरोगी)",
        "lang": "mr",
        "langName": "मराठी (Marathi)",
        "gender": "female",
        "badge": "स्त्री आवाज",
        "desc": "नैसर्गिक व स्पष्ट मराठी आवाज (Default)"
    },
    {
        "id": "mr-IN-ManoharNeural",
        "name": "Manohar (मनोहर)",
        "lang": "mr",
        "langName": "मराठी (Marathi)",
        "gender": "male",
        "badge": "पुरुष आवाज",
        "desc": "गंभीर व विश्वासू शेती मार्गदर्शक"
    },
    {
        "id": "hi-IN-SwaraNeural",
        "name": "Swara (स्वरा)",
        "lang": "hi",
        "langName": "हिंदी (Hindi)",
        "gender": "female",
        "badge": "महिला आवाज़",
        "desc": "मधुर व स्पष्ट कृषी सहाय्यक"
    },
    {
        "id": "hi-IN-MadhurNeural",
        "name": "Madhur (मधुर)",
        "lang": "hi",
        "langName": "हिंदी (Hindi)",
        "gender": "male",
        "badge": "पुरुष आवाज़",
        "desc": "आत्मविश्वासू व भारदस्त आवाज़"
    },
    {
        "id": "en-IN-NeerjaNeural",
        "name": "Neerja",
        "lang": "en",
        "langName": "English (India)",
        "gender": "female",
        "badge": "Female Voice",
        "desc": "Fluent Indian English specialist"
    },
    {
        "id": "en-IN-PrabhatNeural",
        "name": "Prabhat",
        "lang": "en",
        "langName": "English (India)",
        "gender": "male",
        "badge": "Male Voice",
        "desc": "Professional agricultural advisor"
    }
]

def clean_speech_text(text):
    if not text:
        return ""
    t = re.sub(r'\!\[.*?\]\(.*?\)', '', text)
    t = re.sub(r'\[([^\]]+)\]\([^\)]*\)', r'\1', t)
    t = re.sub(r'https?://\S+', '', t)
    t = re.sub(r'<[^>]+>', '', t)
    t = re.sub(r'[\*\#\_`~]', '', t)
    t = re.sub(r'^\s*[-+*•]\s+', '', t, flags=re.MULTILINE)
    t = re.sub(r'^\s*\d+\.\s+', '', t, flags=re.MULTILINE)
    t = re.sub(r'\s+', ' ', t).strip()
    return t

async def _edge_tts_async(text, voice, rate="+0%", pitch="+0Hz"):
    comm = edge_tts.Communicate(text, voice=voice, rate=rate, pitch=pitch)
    buf = io.BytesIO()
    async for chunk in comm.stream():
        if chunk["type"] == "audio":
            buf.write(chunk["data"])
    return buf.getvalue()

def fallback_gtts(text, lang='mr'):
    try:
        url = 'https://translate.google.com/translate_tts'
        params = {'ie': 'UTF-8', 'tl': lang, 'client': 'tw-ob', 'q': text[:200]}
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(url, params=params, headers=headers, timeout=4)
        if r.status_code == 200:
            return r.content
    except Exception as e:
        print(f"Fallback gTTS error: {e}")
    return b""

@app.route('/api/tts/voices', methods=['GET'])
def get_tts_voices():
    """Return all available Indian neural voices."""
    return jsonify({
        "status": "success",
        "voices": TTS_VOICES
    })

@app.route('/api/tts', methods=['GET', 'POST'])
def handle_tts():
    """Stream high-fidelity neural audio for chatbot responses."""
    try:
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            raw_text = data.get("text", "")
            voice = data.get("voice", "")
            rate = data.get("rate", "+0%")
            pitch = data.get("pitch", "+0Hz")
            lang = data.get("lang", "")
        else:
            raw_text = request.args.get("text", "")
            voice = request.args.get("voice", "")
            rate = request.args.get("rate", "+0%")
            pitch = request.args.get("pitch", "+0Hz")
            lang = request.args.get("lang", "")

        cleaned = clean_speech_text(raw_text)
        if not cleaned:
            return jsonify({"error": "Empty text"}), 400

        # Language / Voice Auto-detection if not specified
        if not voice:
            has_devanagari = bool(re.search(r'[\u0900-\u097F]', cleaned))
            if has_devanagari:
                # check for typical Marathi keywords
                if re.search(r'(आहे|नाही|करावे|करा|पाणी|पीक|शेतकरी|रोगाची|व्यवस्थापन)', cleaned):
                    voice = "mr-IN-AarohiNeural"
                else:
                    voice = "hi-IN-SwaraNeural"
            else:
                voice = "en-IN-NeerjaNeural"

        # Validate voice is supported
        valid_voice_ids = [v["id"] for v in TTS_VOICES]
        if voice not in valid_voice_ids:
            voice = "mr-IN-AarohiNeural"

        # Check Cache
        cache_key = hashlib.md5(f"{cleaned}_{voice}_{rate}_{pitch}".encode('utf-8')).hexdigest()
        cache_path = os.path.join(TTS_CACHE_DIR, f"{cache_key}.mp3")

        if os.path.exists(cache_path) and os.path.getsize(cache_path) > 0:
            with open(cache_path, "rb") as f:
                audio_data = f.read()
        else:
            try:
                # Run async edge_tts
                audio_data = asyncio.run(_edge_tts_async(cleaned[:2500], voice, rate, pitch))
            except Exception as tts_err:
                print(f"Edge-TTS failed: {tts_err}. Falling back to Google Translate TTS.")
                # determine lang code from voice id
                lang_code = "mr" if "mr-" in voice else ("hi" if "hi-" in voice else "en")
                audio_data = fallback_gtts(cleaned[:250], lang=lang_code)

            if audio_data:
                try:
                    with open(cache_path, "wb") as f:
                        f.write(audio_data)
                except Exception:
                    pass

        if not audio_data:
            return jsonify({"error": "Unable to synthesize audio"}), 500

        return Response(
            audio_data,
            mimetype="audio/mpeg",
            headers={
                "Content-Type": "audio/mpeg",
                "Content-Length": str(len(audio_data)),
                "Accept-Ranges": "bytes",
                "Cache-Control": "public, max-age=86400",
                "Access-Control-Allow-Origin": "*"
            }
        )

    except Exception as e:
        print(f"TTS endpoint error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
