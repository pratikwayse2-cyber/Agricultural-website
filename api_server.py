from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import hashlib
import json
import secrets
import sqlite3
import tempfile
from datetime import datetime, timezone
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")
API_NINJAS_KEY = os.getenv("API_NINJAS_KEY")
API_NINJAS_MCP_URL = "https://mcp.api-ninjas.com/mcp"

# Initialize the Gemini Client only when credentials are present.
client = None
if API_KEY:
    try:
        from google import genai
        client = genai.Client(api_key=API_KEY)
    except Exception as exc:
        print(f"GenAI Client initialization note: {exc}")

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
    if not token:
        return None
    return database.execute(
        """SELECT users.id, users.email FROM sessions
           JOIN users ON users.id = sessions.user_id WHERE sessions.token = ?""",
        (token,),
    ).fetchone()


def call_api_ninjas_mcp(messages, session_id=None):
    """Run a short MCP session and return the JSON-RPC responses."""
    if not API_NINJAS_KEY:
        raise RuntimeError("API_NINJAS_KEY not found in environment. Add it to your .env file.")

    responses = []
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "X-Api-Key": API_NINJAS_KEY,
    }
    for message in messages:
        request_headers = dict(headers)
        if session_id:
            request_headers["Mcp-Session-Id"] = session_id
        response = requests.post(
            API_NINJAS_MCP_URL,
            headers=request_headers,
            json=message,
            timeout=20,
        )
        try:
            payload = response.json()
        except ValueError:
            data_line = next(
                (line[5:].strip() for line in response.text.splitlines()
                 if line.startswith("data:")),
                None,
            )
            payload = json.loads(data_line) if data_line else {}
        if not response.ok:
            detail = payload.get("error", {}).get("message", response.reason)
            raise RuntimeError(f"API Ninjas MCP error ({response.status_code}): {detail}")
        if payload.get("error"):
            raise RuntimeError(payload["error"].get("message", "MCP request failed."))
        session_id = response.headers.get("Mcp-Session-Id", session_id)
        responses.append(payload)
    return responses, session_id


def extract_mcp_price(payload):
    """Extract a numeric price from either structured MCP or text content."""
    result = payload.get("result", {})
    structured = result.get("structuredContent", {})
    candidates = [structured, result]
    for item in result.get("content", []):
        if isinstance(item, dict):
            candidates.append(item.get("text", item))
    for candidate in candidates:
        if isinstance(candidate, str):
            try:
                candidate = json.loads(candidate)
            except ValueError:
                continue
        if isinstance(candidate, dict):
            for key in ("price", "value", "last_price"):
                if key in candidate:
                    try:
                        return float(candidate[key])
                    except (TypeError, ValueError):
                        pass
    return None


initialize_database()

# 1. Serve the standalone chat page at http://127.0.0
@app.route('/', methods=['GET']) 
def index():
    return send_from_directory(os.path.dirname(__file__), 'chatbot_page.html')

# 2. Serve your website with the popup menu at http://127.0.0website.html
@app.route('/website.html', methods=['GET'])
def website():
    return send_from_directory(os.path.dirname(__file__), 'website.html')


@app.route('/login.html', methods=['GET'])
def login_page():
    return send_from_directory(os.path.dirname(__file__), 'login.html')


@app.route('/<path:filename>', methods=['GET'])
def page_file(filename):
    # Keep the static server limited to the site's HTML pages.
    if not filename.endswith(".html") or "/" in filename or "\\" in filename:
        return jsonify({"error": "Page not found."}), 404
    return send_from_directory(os.path.dirname(__file__), filename)


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


@app.route('/api/logout', methods=['POST'])
def logout_endpoint():
    token = request.headers.get("X-Session-Token")
    if token:
        with get_db() as database:
            database.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return jsonify({"ok": True})


@app.route('/api/clear-history', methods=['POST', 'DELETE'])
def clear_history_endpoint():
    with get_db() as database:
        user = get_authenticated_user(database)
        if user:
            database.execute("DELETE FROM messages WHERE user_id = ?", (user["id"],))
            database.commit()
    return jsonify({"ok": True, "message": "Chat history cleared successfully."})


@app.route('/api/commodity-prices', methods=['GET'])
def commodity_prices_endpoint():
    commodities = ("wheat", "corn", "coffee", "sugar")
    try:
        _, session_id = call_api_ninjas_mcp([{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "agribot-market", "version": "1.0"},
            },
        }])
        tools_response, session_id = call_api_ninjas_mcp([
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ], session_id)
        tools = tools_response[-1].get("result", {}).get("tools", [])
        tool = next(
            (
                item for item in tools
                if "price" in f"{item.get('name', '')} {item.get('description', '')}".lower()
                and "commod" in f"{item.get('name', '')} {item.get('description', '')}".lower()
            ),
            None,
        )
        if not tool:
            raise RuntimeError("No commodity price tool is available for this API account.")
        schema = tool.get("inputSchema", {})
        properties = schema.get("properties", {})
        argument_name = next(
            (name for name in ("ticker", "symbol", "commodity", "name") if name in properties),
            next(iter(properties), "ticker"),
        )
        prices = {}
        for index, commodity in enumerate(commodities, start=3):
            response, session_id = call_api_ninjas_mcp([{
                "jsonrpc": "2.0",
                "id": index,
                "method": "tools/call",
                "params": {"name": tool["name"], "arguments": {argument_name: commodity}},
            }], session_id)
            prices[commodity] = extract_mcp_price(response[-1])
        return jsonify({"prices": prices, "updated_at": now_iso()})
    except requests.RequestException as error:
        return jsonify({"error": f"Unable to reach API Ninjas: {error}"}), 502
    except (RuntimeError, ValueError, KeyError) as error:
        return jsonify({"error": str(error)}), 502


# 3. Handle messages or audio files sent from the chat windows
@app.route('/api/chat', methods=['POST'])
def chat_endpoint():
    message_content = []
    temp_file_path = None
    uploaded_file = None

    try:
        database = get_db()
        user = get_authenticated_user(database)
        if not user:
            database.close()
            return jsonify({"error": "Please sign in before using AgroAI."}), 401

        input_file = request.files.get("pdf") or request.files.get("audio")
        if input_file and input_file.filename:
            extension = os.path.splitext(input_file.filename)[1].lower()
            is_pdf = request.files.get("pdf") is not None
            if is_pdf and (extension != ".pdf" or input_file.mimetype not in ("application/pdf", "application/octet-stream")):
                database.close()
                return jsonify({"error": "Please upload a valid PDF file."}), 415
            suffix = extension or (".pdf" if is_pdf else ".wav")
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                input_file.save(temp_file.name)
                temp_file_path = temp_file.name
            file_size = os.path.getsize(temp_file_path)
            if is_pdf and file_size > 10 * 1024 * 1024:
                database.close()
                return jsonify({"error": "PDF files must be 10 MB or smaller."}), 413

            uploaded_file = client.files.upload(
                file=temp_file_path,
                config={
                    "mime_type": input_file.mimetype or ("application/pdf" if is_pdf else "audio/wav"),
                    "display_name": input_file.filename,
                },
            )
            message_content.append(uploaded_file)
            if is_pdf:
                message_content.append(
                    "Read this agricultural PDF carefully. Use its contents to answer the farmer's question, "
                    "and mention when a recommendation comes directly from the document."
                )
                database.execute(
                    """INSERT INTO documents
                       (user_id, filename, mime_type, file_size, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (user["id"], input_file.filename, input_file.mimetype or "application/pdf",
                     file_size, now_iso()),
                )
            else:
                message_content.append(
                    "Please listen to this audio message from a farmer. Understand their language "
                    "(English, Hindi, or Marathi), transcribe it, and provide your reply following your system instructions."
                )

        # Check if the user sent text via multipart form
        if 'message' in request.form and request.form['message'].strip():
            message_content.append(request.form['message'])
            
        # Fallback to JSON check if no form data was submitted
        if not message_content and request.is_json:
            data = request.get_json(force=True)
            text_msg = data.get("message")
            if text_msg:
                message_content.append(text_msg)

        # If nothing was provided, return an error
        if not message_content:
            database.close()
            return jsonify({"error": "Missing 'message' or 'audio' in request"}), 400

        # Specialized rules for Agri AI / Krishi Mitra farming assistant
        farming_instructions = (
            "You AgriBot, an expert AI Agricultural Consultant. Your mission is to help farmers "
            "adopt modern technology, sustainable farming techniques, and maximize crop yields.\n\n"
            "LANGUAGE RULES:\n"
            "1. You are completely multilingual. You must understand questions asked in English, Hindi, and Marathi.\n"
            "2. Always reply back in the EXACT same language or script used by the farmer. If they type or speak in Marathi, reply in Marathi (Devanagari script). If they use Hindi, reply in Hindi. If they use Hinglish or Marathish (Latin/English script to spell out native words), reply in clear, readable Hindi or Marathi.\n\n"
            "FORMATTING & STRUCTURE RULES (CRITICAL):\n"
            "1. NEVER give long paragraphs or disordered walls of text.\n"
            "2. ALWAYS start with a very brief, 1-sentence summary or direct answer.\n"
            "3. Use clean, numbered lists (1, 2, 3) for step-by-step procedures or sequential actions.\n"
            "4. Use clear bullet points (•) for presenting facts, tips, or options.\n"
            "5. Keep every point short, punchy, and highly practical.\n"
            "6. Use bold text for key terms to make the response highly scannable.\n\n"
            "CONTENT GUIDELINES:\n"
            "1. Explain advanced concepts (like hydroponics, drone monitoring, precision farming, and IoT soil sensors) "
            "using simple, jargon-free language that everyday farmers can easily understand.\n"
            "2. Provide step-by-step guidance on pest control, crop rotation, organic fertilizers, and water conservation.\n"
            "3. Keep your tone encouraging, patient, respectful, and highly practical.\n"
            "4. If a farmer asks an irrelevant question, gently guide them back to agriculture, weather, or technology."
        )

        # Create the chat session
        chat = client.chats.create(
            model="gemini-3.6-flash",
            config={
                "system_instruction": farming_instructions
            }
        )
        
        # Send the accumulated content (Text, Audio object, or both)
        response = chat.send_message(message_content)
        reply = response.text
        user_text = request.form.get("message")
        if not user_text and request.is_json:
            user_text = (request.get_json(silent=True) or {}).get("message")
        if not user_text and request.files.get("pdf"):
            user_text = f"[PDF: {request.files['pdf'].filename}]"
        timestamp = now_iso()
        database.execute(
            "INSERT INTO messages (user_id, role, content, created_at) VALUES (?, 'user', ?, ?)",
            (user["id"], user_text or "[Voice message]", timestamp),
        )
        database.execute(
            "INSERT INTO messages (user_id, role, content, created_at) VALUES (?, 'assistant', ?, ?)",
            (user["id"], reply, timestamp),
        )
        database.commit()
        database.close()
        return jsonify({"reply": reply})

    except Exception as e:
        if "database" in locals():
            database.close()
        return jsonify({"error": str(e)}), 500

    finally:
        # Cleanup: Delete the local temporary file and remote Gemini file reference
        if temp_file_path and os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except Exception:
                pass
        if uploaded_file:
            try:
                client.files.delete(name=uploaded_file.name)
            except Exception:
                pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
