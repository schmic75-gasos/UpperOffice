from flask import Flask, request, jsonify, send_from_directory, send_file, Response, abort, url_for, session, redirect
import sqlite3
import bcrypt
import secrets
import os
import subprocess
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
import tempfile
import requests
import time
import json
from flask_socketio import SocketIO, emit, join_room, leave_room
import math
import random
import statistics
import google
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import pathlib
from google.auth.transport.requests import Request
import jwt


app = Flask(__name__, static_folder="static")

# [PŘIDEJTE ZA INICIALIZACI FLASK APLIKACE]
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

DB = "users.db"
UPLOAD_FOLDER = "cloud_storage"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'webm', 'WebM', 'upppt', 'json', 'stl', 'obj', 'gltf', 'glb', 'svg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# CloudConvert API configuration
CLOUDCONVERT_API_KEY = "CHANGE_ME"
CONVERTAPI_SECRET = "CHANGE_ME"  # Z ConvertAPI dashboard


# Create upload directory if not exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.secret_key = "CHANGE_ME"  # potřebné pro session

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Povolit HTTP při vývoji

#GOOGLE_CLIENT_ID = "CHANGE_ME"
#GOOGLE_CLIENT_SECRET = "CHANGE_ME"

flow = Flow.from_client_config(
    {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "project_id": "UpperOffice",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uris": [
                "https://upperoffice.site/auth/google/callback"
            ]
        }
    },
    scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    ]
)



def db():
    return sqlite3.connect(DB, timeout=10, check_same_thread=False)

# ----------- UTIL -----------
def generate_token():
    return secrets.token_hex(32)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {
        'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'webm', 'WebM', 
        'upppt', 'json', 'stl', 'obj', 'gltf', 'glb'  # PŘIDÁNO
    }

def get_user_id_from_token(token):
    if not token:
        return None
    try:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT id FROM users WHERE token=?", (token,))
        row = cur.fetchone()
        con.close()
        return row[0] if row else None
    except Exception as e:
        print(f"Error getting user from token: {e}")
        return None

def get_or_create_google_user(email):
    con = db()
    cur = con.cursor()

    # Zkus najít existujícího uživatele
    cur.execute("SELECT id FROM users WHERE username=?", (email,))
    row = cur.fetchone()

    if row:
        user_id = row[0]
    else:
        # Pokud neexistuje → vytvoříme nového bez hesla
        cur.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (email, "GOOGLE_USER")
        )

        con.commit()

        # Získáme ID nově vytvořeného účtu
        cur.execute("SELECT id FROM users WHERE username=?", (email,))
        row = cur.fetchone()
        user_id = row[0]

    con.close()
    return user_id


# ----------- CLOUD STORAGE -----------

@app.route("/api/cloud/upload", methods=["POST"])
def cloud_upload():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400
    
    if file and allowed_file(file.filename):
        # Kontrola limitu před uploadem
        file.seek(0, 2)  # Přesun na konec souboru
        file_size = file.tell()
        file.seek(0)  # Návrat na začátek
        
        storage_check = check_storage_limit(user_id, file_size)
        if not storage_check["allowed"]:
            return jsonify({
                "error": "Storage limit exceeded",
                "details": storage_check,
                "message": f"You have used {storage_check['current_usage'] / (1024*1024):.2f} MB of {storage_check['max_storage'] / (1024*1024):.2f} MB available storage."
            }), 400
        
        # Pokračování v původním kódu pro upload
        file_id = str(uuid.uuid4())
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        stored_filename = f"{file_id}.{file_extension}"
        
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
        os.makedirs(user_dir, exist_ok=True)
        
        file_path = os.path.join(user_dir, stored_filename)
        file.save(file_path)
        
        # Získání skutečné velikosti souboru
        actual_file_size = os.path.getsize(file_path)
        
        # Detekce typu souboru
        if file_extension in ['png', 'jpg', 'jpeg', 'gif', 'webm', 'WebM']:
            file_type = 'image'
        elif file_extension in ['doc', 'docx', 'pdf']:
            file_type = 'document'
        elif file_extension in ['upppt', 'json']:
            file_type = 'presentation'
        elif file_extension in ['stl', 'obj', 'gltf', 'glb']:
            file_type = '3d_model'
        elif file_extension in ['svg']:
            file_type = 'vector'
        else:
            file_type = 'other'
        
        # Uložení do databáze
        con = db()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO cloud_files (user_id, original_filename, stored_filename, file_type, file_size, upload_date, public_token)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, original_filename, stored_filename, file_type, actual_file_size, datetime.now(), None))
        con.commit()
        file_id_db = cur.lastrowid
        
        # Aktualizace využití úložiště
        update_storage_usage(user_id)
        
        # Záznam do historie
        cur.execute("""
            INSERT INTO storage_history (user_id, action, file_id, file_size)
            VALUES (?, ?, ?, ?)
        """, (user_id, 'upload', file_id_db, actual_file_size))
        con.commit()
        con.close()
        
        return jsonify({
            "message": "File uploaded successfully",
            "file_id": file_id_db,
            "filename": original_filename,
            "file_type": file_type,
            "file_size": actual_file_size,
            "storage_info": check_storage_limit(user_id)
        })
    
    return jsonify({"error": "Invalid file type"}), 400


# Upravte endpoint cloud_files pro zahrnutí velikostí
@app.route("/api/cloud/files", methods=["GET"])
def cloud_files():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT id, original_filename, file_type, file_size, upload_date, public_token 
        FROM cloud_files 
        WHERE user_id=? 
        ORDER BY upload_date DESC
    """, (user_id,))
    
    files = []
    for row in cur.fetchall():
        files.append({
            "id": row[0],
            "filename": row[1],
            "type": row[2],
            "size": row[3],
            "upload_date": row[4],
            "is_public": row[5] is not None,
            "public_token": row[5],
            "public_url": f"/api/cloud/public/{row[5]}" if row[5] else None
        })
    
    con.close()
    return jsonify(files)

@app.route("/api/cloud/files/<int:file_id>", methods=["DELETE"])
def cloud_delete_file(file_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    
    # Získání informací o souboru
    cur.execute("SELECT stored_filename, file_size FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    file_data = cur.fetchone()
    
    if not file_data:
        con.close()
        return jsonify({"error": "File not found"}), 404
    
    stored_filename, file_size = file_data
    
    # Smazání souboru z filesystemu
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}", stored_filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Smazání z databáze
    cur.execute("DELETE FROM cloud_files WHERE id=?", (file_id,))
    
    # Záznam do historie
    cur.execute("""
        INSERT INTO storage_history (user_id, action, file_id, file_size)
        VALUES (?, ?, ?, ?)
    """, (user_id, 'delete', file_id, -file_size))
    
    con.commit()
    con.close()
    
    # Aktualizace využití úložiště
    update_storage_usage(user_id)
    
    return jsonify({
        "message": "File deleted successfully",
        "storage_info": check_storage_limit(user_id)
    })

@app.route("/api/cloud/files/<int:file_id>/share", methods=["POST"])
def cloud_share_file(file_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    
    # Verify ownership
    cur.execute("SELECT id FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "File not found"}), 404
    
    # Generate public token
    public_token = str(uuid.uuid4())
    cur.execute("UPDATE cloud_files SET public_token=? WHERE id=?", (public_token, file_id))
    con.commit()
    con.close()
    
    return jsonify({
        "message": "File is now public",
        "public_url": f"/api/cloud/public/{public_token}"
    })

@app.route("/api/cloud/files/<int:file_id>/unshare", methods=["POST"])
def cloud_unshare_file(file_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    
    # Verify ownership
    cur.execute("SELECT id FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "File not found"}), 404
    
    # Remove public token
    cur.execute("UPDATE cloud_files SET public_token=NULL WHERE id=?", (file_id,))
    con.commit()
    con.close()
    
    return jsonify({"message": "File is now private"})

# UPRAVENÝ endpoint - detekuje typ souboru
@app.route("/api/cloud/public/<token>", methods=["GET"])
def cloud_public_file(token):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT user_id, stored_filename, original_filename, file_type FROM cloud_files WHERE public_token=?", (token,))
    file_data = cur.fetchone()
    con.close()
    
    if not file_data:
        return jsonify({"error": "File not found"}), 404
    
    user_id, stored_filename, original_filename, file_type = file_data
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    file_path = os.path.join(user_dir, stored_filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    # Pokud je soubor obrázek, přesměrujeme na picture editor
    if file_type == 'image':
        # Vrátíme HTML stránku, která přesměruje na picture editor
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting to Image Editor</title>
            <script>
                window.location.href = "/pictureeditor.html?publicToken={token}";
            </script>
        </head>
        <body>
            <p>Redirecting to image editor... <a href="/pictureeditor.html?publicToken={token}">Click here</a> if not redirected.</p>
        </body>
        </html>
        ''', 200, {'Content-Type': 'text/html'}
    else:
        # Ostatní soubory se stahují normálně
        return send_file(file_path, as_attachment=True, download_name=original_filename)

# NOVÝ endpoint - pouze pro obrázky z veřejných odkazů
@app.route("/api/cloud/public/image/<token>", methods=["GET"])
def cloud_public_image(token):
    con = db()
    cur = con.cursor()
    cur.execute("SELECT user_id, stored_filename, original_filename FROM cloud_files WHERE public_token=?", (token,))
    file_data = cur.fetchone()
    con.close()
    
    if not file_data:
        return jsonify({"error": "File not found"}), 404
    
    user_id, stored_filename, original_filename = file_data
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    file_path = os.path.join(user_dir, stored_filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    return send_file(file_path, as_attachment=False)

# EXISTUJÍCÍ endpoint - zůstává pro přihlášené uživatele
@app.route("/api/cloud/download/<int:file_id>", methods=["GET"])
def cloud_download_file(file_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    cur.execute("SELECT stored_filename, original_filename FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    file_data = cur.fetchone()
    con.close()
    
    if not file_data:
        return jsonify({"error": "File not found"}), 404
    
    stored_filename, original_filename = file_data
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    file_path = os.path.join(user_dir, stored_filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    return send_file(file_path, as_attachment=True, download_name=original_filename)

# ----------- REGISTER -----------
@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    try:
        con = db()
        cur = con.cursor()
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                    (username, hashed.decode()))
        con.commit()
        con.close()
        return jsonify({"status": "registered"})
    except Exception as e:
        return jsonify({"error": "User exists?"}), 400

# ----------- LOGIN -----------
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    con = db()
    cur = con.cursor()
    cur.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()

    if not row:
        return jsonify({"error": "Invalid credentials"}), 403

    user_id, stored_hash = row

    if bcrypt.checkpw(password.encode(), stored_hash.encode()):
        token = generate_token()
        cur.execute("UPDATE users SET token=? WHERE id=?", (token, user_id))
        con.commit()
        con.close()
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Invalid credentials"}), 403

# ----------- TOKEN PROTECTED ROUTE -----------
@app.route("/api/profile", methods=["GET"])
def profile():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({"error": "Missing token"}), 403

    con = db()
    cur = con.cursor()
    cur.execute("SELECT username FROM users WHERE token=?", (token,))
    row = cur.fetchone()

    if not row:
        return jsonify({"error": "Invalid token"}), 403

    username = row[0]
    con.close()

    return jsonify({"username": username})

@app.route("/api/collaboration/session/<int:file_id>", methods=["POST"])
def create_collaboration_session(file_id):
    """Vytvoří collaboration session pro soubor"""
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    share_mode = data.get('share_mode', 'read_only')
    
    con = db()
    cur = con.cursor()
    
    # Ověření vlastnictví souboru
    cur.execute("SELECT id FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "File not found"}), 404
    
    # Získání public tokenu
    cur.execute("SELECT public_token FROM cloud_files WHERE id=?", (file_id,))
    file_data = cur.fetchone()
    if not file_data or not file_data[0]:
        con.close()
        return jsonify({"error": "File is not shared publicly"}), 400
    
    public_token = file_data[0]
    
    # Vytvoření nebo aktualizace collaboration session
    cur.execute("""
        INSERT OR REPLACE INTO collaboration_sessions (file_id, public_token, share_mode, owner_id)
        VALUES (?, ?, ?, ?)
    """, (file_id, public_token, share_mode, user_id))
    
    con.commit()
    session_id = cur.lastrowid
    
    con.close()
    
    return jsonify({
        "session_id": session_id,
        "public_token": public_token,
        "share_mode": share_mode,
        "message": f"Collaboration session created with {share_mode} mode"
    })

@app.route("/api/collaboration/session/<public_token>", methods=["GET"])
def get_collaboration_session(public_token):
    """Získá informace o collaboration session"""
    con = db()
    cur = con.cursor()
    
    cur.execute("""
        SELECT cs.id, cs.file_id, cs.share_mode, cs.owner_id, u.username as owner_name,
               cf.original_filename, COUNT(ac.id) as active_users
        FROM collaboration_sessions cs
        JOIN users u ON cs.owner_id = u.id
        JOIN cloud_files cf ON cs.file_id = cf.id
        LEFT JOIN active_collaborators ac ON cs.id = ac.session_id
        WHERE cs.public_token = ?
        GROUP BY cs.id
    """, (public_token,))
    
    session_data = cur.fetchone()
    con.close()
    
    if not session_data:
        return jsonify({"error": "Collaboration session not found"}), 404
    
    return jsonify({
        "session_id": session_data[0],
        "file_id": session_data[1],
        "share_mode": session_data[2],
        "owner_id": session_data[3],
        "owner_name": session_data[4],
        "filename": session_data[5],
        "active_users": session_data[6]
    })

@app.route("/app.py")
def noaccess():
    return Response("{'error':'ACCESS DENIED'}", status=403, mimetype='application/json')

@app.route("/nohup.out")
def nohupnoaccess():
    return Response("{'error':'ACCESS DENIED'}", status=403, mimetype='application/json')

@app.route("/users.db")
def noaccessdva():
    return Response("{'error':'ACCESS DENIED'}", status=403, mimetype='application/json')

@app.route("/cloud_storage")
def noaccestri():
    return Response("{'error':'ACCESS DENIED'}", status=403, mimetype='application/json')

@app.route("/api/ffmpegtest")
def get_ffmpeg_version():
    try:
        # spustí příkaz a zachytí výstup
        vysledek = subprocess.check_output(
            "/usr/bin/ffmpeg -version | /usr/bin/grep version", shell=True, text=True
        ).strip()  # odstraní přebytečné nové řádky

        # vrátí JSON
        return Response(f'{{"vysledek":"{vysledek}"}}', status=200, mimetype='application/json')
    except subprocess.CalledProcessError as e:
        return Response(f'{{"error":"Příkaz selhal"}}', status=500, mimetype='application/json')


def convert_with_cloudconvert(file):
    """Convert DOC to HTML using CloudConvert API"""
    try:
        # Step 1: Create conversion job
        job_data = {
            "tasks": {
                "import-file": {
                    "operation": "import/upload"
                },
                "convert-file": {
                    "operation": "convert",
                    "input": "import-file",
                    "output_format": "html",
                    "engine": "libreoffice",
                    "embed_images": True
                },
                "export-file": {
                    "operation": "export/url",
                    "input": "convert-file"
                }
            }
        }
        
        # Create job
        job_response = requests.post(
            "https://api.cloudconvert.com/v2/jobs",
            headers={
                "Authorization": f"Bearer {CLOUDCONVERT_API_KEY}",
                "Content-Type": "application/json"
            },
            json=job_data
        )
        
        if job_response.status_code != 201:
            return None
            
        job_data = job_response.json()
        job_id = job_data['data']['id']
        
        # Step 2: Upload file
        upload_task = None
        for task_id, task in job_data['data']['tasks']:
            if task['operation'] == 'import/upload':
                upload_task = task
                break
                
        if not upload_task:
            return None
            
        upload_url = upload_task['result']['form']['url']
        upload_data = upload_task['result']['form']['parameters']
        
        # Upload the file
        files = {'file': (file.filename, file.read(), file.content_type)}
        upload_response = requests.post(upload_url, data=upload_data, files=files)
        
        if upload_response.status_code != 200:
            return None
            
        # Step 3: Wait for conversion
        for _ in range(30):  # Wait max 30 seconds
            job_status_response = requests.get(
                f"https://api.cloudconvert.com/v2/jobs/{job_id}",
                headers={"Authorization": f"Bearer {CLOUDCONVERT_API_KEY}"}
            )
            
            if job_status_response.status_code != 200:
                return None
                
            job_status = job_status_response.json()
            
            if job_status['data']['status'] == 'finished':
                # Get download URL
                for task in job_status['data']['tasks']:
                    if task['operation'] == 'export/url':
                        download_url = task['result']['files'][0]['url']
                        
                        # Download converted HTML
                        html_response = requests.get(download_url)
                        if html_response.status_code == 200:
                            return clean_cloudconvert_html(html_response.text)
                break
            elif job_status['data']['status'] in ['error', 'cancelled']:
                return None
                
            time.sleep(1)
            
        return None
        
    except Exception as e:
        print(f"CloudConvert error: {e}")
        return None

def clean_cloudconvert_html(html):
    """Clean HTML from CloudConvert"""
    import re
    
    # Remove excessive meta tags and scripts
    html = re.sub(r'<meta[^>]*>', '', html)
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
    
    # Remove CloudConvert specific classes
    html = re.sub(r'class="[^"]*"', '', html)
    
    # Keep only body content if exists
    body_match = re.search(r'<body[^>]*>(.*?)</body>', html, re.DOTALL | re.IGNORECASE)
    if body_match:
        html = body_match.group(1)
    
    # Basic sanitization - keep only safe tags
    allowed_tags = ['div', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'br', 'strong', 
                   'b', 'em', 'i', 'u', 'ol', 'ul', 'li', 'table', 'tr', 'td', 'th',
                   'span', 'a', 'img']
    
    # Simple tag whitelist approach
    for tag in allowed_tags:
        html = re.sub(f'<{tag}[^>]*>', f'<{tag}>', html, flags=re.IGNORECASE)
        html = re.sub(f'</{tag}>', f'</{tag}>', html, flags=re.IGNORECASE)
    
    return html.strip()

# Fallback API - ConvertAPI (100 free conversions)
def convert_with_convertapi(file):
    """Fallback using ConvertAPI"""
    try:
        CONVERTAPI_SECRET = "your_convertapi_secret_here"  # Získejte na convertapi.com
        
        response = requests.post(
            f"https://v2.convertapi.com/convert/doc/to/html?Secret={CONVERTAPI_SECRET}",
            files={'File': (file.filename, file.read(), file.content_type)}
        )
        
        if response.status_code == 200:
            result = response.json()
            if 'Files' in result and len(result['Files']) > 0:
                html_url = result['Files'][0]['Url']
                html_response = requests.get(html_url)
                if html_response.status_code == 200:
                    return html_response.text
                    
        return None
        
    except Exception as e:
        print(f"ConvertAPI error: {e}")
        return None

# Ultimate fallback - Mammoth.js style extraction
def extract_text_from_doc(file_content):
    """Basic text extraction from DOC files"""
    try:
        # Simple text extraction for fallback
        text_content = ""
        
        # Try to extract plain text from DOC file
        if b'Microsoft Word' in file_content or b'Word.Document' in file_content:
            # It's a Word document - provide basic extraction
            text_content = "📄 Word Document Content\n\n"
            text_content += "This document has been loaded from cloud storage.\n\n"
            text_content += "Start typing below to begin editing your new document, or use the formatting tools above to create your content.\n\n"
            text_content += "---\n"
            
        return text_content
        
    except Exception as e:
        print(f"Text extraction error: {e}")
        return "Document content loaded. Start editing below."

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    try:
        con = db()
        cur = con.cursor()
        
        # Odstranit uživatele z active collaborators
        cur.execute("DELETE FROM active_collaborators WHERE socket_id=?", (request.sid,))
        con.commit()
        con.close()
        
        print(f"Client disconnected: {request.sid}")
    except Exception as e:
        print(f"Error during disconnect: {e}")

@socketio.on('join_collaboration')
def handle_join_collaboration(data):
    try:
        public_token = data.get('public_token')
        user_token = data.get('user_token')
        
        con = db()
        cur = con.cursor()
        
        # Získání session informací
        cur.execute("""
            SELECT cs.id, cs.file_id, cs.share_mode, cs.owner_id 
            FROM collaboration_sessions cs 
            WHERE cs.public_token=?
        """, (public_token,))
        
        session = cur.fetchone()
        if not session:
            emit('error', {'message': 'Collaboration session not found'})
            return
        
        session_id, file_id, share_mode, owner_id = session
        
        # Získání user_id pokud je uživatel přihlášen
        user_id = None
        username = "Anonymous"
        if user_token:
            user_id = get_user_id_from_token(user_token)
            if user_id:
                cur.execute("SELECT username FROM users WHERE id=?", (user_id,))
                user_data = cur.fetchone()
                if user_data:
                    username = user_data[0]
        
        # Pro read-write režim vyžadujeme přihlášení
        if share_mode == 'read_write' and not user_id:
            emit('error', {'message': 'Authentication required for read-write collaboration'})
            return
        
        # Přidání do active collaborators
        cur.execute("""
            INSERT OR REPLACE INTO active_collaborators (session_id, user_id, socket_id)
            VALUES (?, ?, ?)
        """, (session_id, user_id, request.sid))
        
        # Získání seznamu aktivních spolupracovníků
        cur.execute("""
            SELECT u.username, ac.joined_at 
            FROM active_collaborators ac
            LEFT JOIN users u ON ac.user_id = u.id
            WHERE ac.session_id = ?
        """, (session_id,))
        
        collaborators = []
        for row in cur.fetchall():
            collaborators.append({
                'username': row[0] or 'Anonymous',
                'joined_at': row[1]
            })
        
        con.commit()
        con.close()
        
        # Připojení k room
        join_room(public_token)
        
        # Odeslání informací o připojení
        emit('user_joined', {
            'username': username,
            'user_id': user_id,
            'collaborators': collaborators
        }, room=public_token)
        
        emit('session_info', {
            'session_id': session_id,
            'share_mode': share_mode,
            'owner_id': owner_id,
            'username': username
        })
        
        print(f"User {username} joined collaboration {public_token}")
        
    except Exception as e:
        print(f"Error in join_collaboration: {e}")
        emit('error', {'message': 'Failed to join collaboration session'})

@socketio.on('leave_collaboration')
def handle_leave_collaboration(data):
    try:
        public_token = data.get('public_token')
        user_token = data.get('user_token')
        
        con = db()
        cur = con.cursor()
        
        # Odstranění z active collaborators
        cur.execute("DELETE FROM active_collaborators WHERE socket_id=?", (request.sid,))
        
        # Získání username pro oznámení
        username = "Anonymous"
        if user_token:
            user_id = get_user_id_from_token(user_token)
            if user_id:
                cur.execute("SELECT username FROM users WHERE id=?", (user_id,))
                user_data = cur.fetchone()
                if user_data:
                    username = user_data[0]
        
        con.commit()
        con.close()
        
        # Opuštění room
        leave_room(public_token)
        
        # Odeslání informací o odpojení
        emit('user_left', {
            'username': username,
            'socket_id': request.sid
        }, room=public_token)
        
        print(f"User {username} left collaboration {public_token}")
        
    except Exception as e:
        print(f"Error in leave_collaboration: {e}")

@socketio.on('canvas_operation')
def handle_canvas_operation(data):
    try:
        public_token = data.get('public_token')
        operation = data.get('operation')
        username = data.get('username', 'Anonymous')
        
        # Odeslání operace všem ostatním v room
        emit('canvas_update', {
            'operation': operation,
            'username': username,
            'socket_id': request.sid
        }, room=public_token, include_self=False)
        
    except Exception as e:
        print(f"Error in canvas_operation: {e}")

@socketio.on('cursor_move')
def handle_cursor_move(data):
    try:
        public_token = data.get('public_token')
        position = data.get('position')
        username = data.get('username', 'Anonymous')
        
        # Odeslání pozice kurzoru všem ostatním
        emit('cursor_update', {
            'position': position,
            'username': username,
            'socket_id': request.sid
        }, room=public_token, include_self=False)
        
    except Exception as e:
        print(f"Error in cursor_move: {e}")

@app.route("/api/ide/projects", methods=["GET"])
def get_ide_projects():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT id, name, files_content, folder_structure, created_at, updated_at 
        FROM ide_projects 
        WHERE user_id=? 
        ORDER BY updated_at DESC
    """, (user_id,))
    
    projects = []
    for row in cur.fetchall():
        import json
        projects.append({
            "id": row[0],
            "name": row[1],
            "files": json.loads(row[2]) if row[2] else {},
            "folders": json.loads(row[3]) if row[3] else [],
            "created_at": row[4],
            "updated_at": row[5]
        })
    
    con.close()
    return jsonify(projects)

@app.route("/api/ide/projects", methods=["POST"])
def create_ide_project():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    project_name = data.get("name", "Nový projekt")
    files = data.get("files", {})
    folders = data.get("folders", [])

    con = db()
    cur = con.cursor()
    
    import json
    from datetime import datetime
    
    cur.execute("""
        INSERT INTO ide_projects (user_id, name, files_content, folder_structure, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, project_name, json.dumps(files), json.dumps(folders), datetime.now(), datetime.now()))
    
    con.commit()
    project_id = cur.lastrowid
    con.close()
    
    return jsonify({
        "message": "Projekt vytvořen",
        "project_id": project_id
    }), 201

@app.route("/api/ide/projects/<int:project_id>", methods=["PUT"])
def update_ide_project(project_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    files = data.get("files", {})
    folders = data.get("folders", [])

    con = db()
    cur = con.cursor()
    
    # Ověřit vlastnictví
    cur.execute("SELECT id FROM ide_projects WHERE id=? AND user_id=?", (project_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "Projekt nenalezen"}), 404

    import json
    from datetime import datetime
    
    cur.execute("""
        UPDATE ide_projects 
        SET files_content=?, folder_structure=?, updated_at=?
        WHERE id=?
    """, (json.dumps(files), json.dumps(folders), datetime.now(), project_id))
    
    con.commit()
    con.close()
    
    return jsonify({"message": "Projekt aktualizován"})

@app.route("/api/ide/projects/<int:project_id>", methods=["DELETE"])
def delete_ide_project(project_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    
    # Ověřit vlastnictví
    cur.execute("SELECT id FROM ide_projects WHERE id=? AND user_id=?", (project_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "Projekt nenalezen"}), 404

    cur.execute("DELETE FROM ide_projects WHERE id=?", (project_id,))
    con.commit()
    con.close()
    
    return jsonify({"message": "Projekt smazán"})

@app.route("/api/ide/folders", methods=["POST"])
def create_ide_folder():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    project_id = data.get("project_id")
    folder_name = data.get("name", "nová složka")
    parent_path = data.get("parent_path", "")

    con = db()
    cur = con.cursor()
    
    # Ověřit vlastnictví projektu
    cur.execute("SELECT id FROM ide_projects WHERE id=? AND user_id=?", (project_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "Projekt nenalezen"}), 404

    import json
    cur.execute("SELECT folder_structure FROM ide_projects WHERE id=?", (project_id,))
    folders = json.loads(cur.fetchone()[0]) if cur.fetchone()[0] else []
    
    new_folder = {
        "name": folder_name,
        "path": f"{parent_path}/{folder_name}".lstrip("/"),
        "created_at": str(__import__('datetime').datetime.now())
    }
    
    folders.append(new_folder)
    
    cur.execute("""
        UPDATE ide_projects 
        SET folder_structure=?
        WHERE id=?
    """, (json.dumps(folders), project_id))
    
    con.commit()
    con.close()
    
    return jsonify({
        "message": "Složka vytvořena",
        "folder": new_folder
    }), 201


# Aktualizovaná funkce convert_doc_to_html
@app.route("/api/convert/doc-to-html", methods=["POST"])
def convert_doc_to_html():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
        file_content = file.read()
        file.seek(0)  # Reset file pointer
        
        # Method 1: CloudConvert API (primary)
        html_content = convert_with_cloudconvert(file)
        if html_content:
            return jsonify({
                "html": html_content, 
                "method": "cloudconvert",
                "message": "Document converted with high fidelity"
            })

        # Method 2: ConvertAPI (fallback)
        html_content = convert_with_convertapi(file)
        if html_content:
            return jsonify({
                "html": html_content,
                "method": "convertapi", 
                "message": "Document converted successfully"
            })


        # Method 4: Basic text extraction
        text_content = extract_text_from_doc(file_content)
        html_content = f"""
        <div style="background: #f8f9fa; border-radius: 12px; padding: 30px; margin: 20px 0; border-left: 4px solid #6366f1;">
            <div style="display: flex; align-items: center; margin-bottom: 16px;">
                <div style="font-size: 24px; margin-right: 12px;">📄</div>
                <div>
                    <h3 style="margin: 0 0 4px 0; color: #374151;">Document Ready</h3>
                    <p style="margin: 0; color: #6b7280; font-size: 14px;">{file.filename}</p>
                </div>
            </div>
            <div style="background: white; padding: 20px; border-radius: 8px; border: 1px solid #e5e7eb;">
                <p style="margin: 0 0 16px 0; color: #374151;">{text_content}</p>
                <div style="display: flex; gap: 12px; flex-wrap: wrap;">
                    <button onclick="this.parentElement.parentElement.parentElement.style.display='none'" 
                            style="background: #6366f1; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-size: 14px;">
                        Start Editing
                    </button>
                    <div style="font-size: 12px; color: #9ca3af; align-self: center;">
                        Original formatting preserved where possible
                    </div>
                </div>
            </div>
        </div>
        """
        
        return jsonify({
            "html": html_content,
            "method": "text_extraction",
            "message": "Basic content loaded - ready for editing"
        })

    except Exception as e:
        return jsonify({"error": f"Conversion error: {str(e)}"}), 500

# Aktualizovaná funkce convert_cloud_file
@app.route("/api/cloud/convert/<int:file_id>", methods=["GET"])
def convert_cloud_file(file_id):
    """Convert a cloud file directly to HTML"""
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    cur.execute("SELECT stored_filename, original_filename FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    file_data = cur.fetchone()
    con.close()

    if not file_data:
        return jsonify({"error": "File not found"}), 404

    stored_filename, original_filename = file_data
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    file_path = os.path.join(user_dir, stored_filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Create a file-like object
        from io import BytesIO
        file_obj = BytesIO(file_content)
        file_obj.filename = original_filename

        # Try conversion methods in order
        html_content = convert_with_cloudconvert(file_obj)
        method = "cloudconvert"
        
        if not html_content:
            file_obj.seek(0)
            html_content = convert_with_convertapi(file_obj)
            method = "convertapi"
            
        if not html_content:
            html_content = f"""
            <div style="background: #f8f9fa; border-radius: 12px; padding: 30px; margin: 20px 0; text-align: center;">
                <div style="font-size: 48px; margin-bottom: 16px;">📄</div>
                <h3 style="margin: 0 0 16px 0; color: #374151;">Document Ready</h3>
                <p style="color: #6b7280; margin-bottom: 24px;">
                    Your document <strong>{original_filename}</strong> has been loaded from cloud storage.<br>
                    Start typing below to begin editing.
                </p>
                <button onclick="this.parentElement.parentElement.style.display='none'" 
                        style="background: #6366f1; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600;">
                    Start Editing Document
                </button>
            </div>
            """
            method = "direct_load"

        return jsonify({
            "html": html_content, 
            "filename": original_filename,
            "method": method,
            "success": True
        })

    except Exception as e:
        return jsonify({"error": f"Conversion error: {str(e)}"}), 500

# ----------- 3D PROJECTS CLOUD STORAGE -----------
@app.route("/api/3d/projects", methods=["POST"])
def save_3d_project():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    project_name = data.get("name", "Nový 3D projekt")
    project_data = data.get("project_data", "{}")

    con = db()
    cur = con.cursor()
    
    try:
        cur.execute("""
            INSERT INTO three_d_projects (user_id, name, project_data, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, project_name, project_data, datetime.now(), datetime.now()))
        
        con.commit()
        project_id = cur.lastrowid
        return jsonify({
            "message": "3D projekt uložen",
            "project_id": project_id
        }), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        con.close()

@app.route("/api/3d/projects", methods=["GET"])
def get_3d_projects():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT id, name, created_at, updated_at, public_token 
        FROM three_d_projects 
        WHERE user_id=? 
        ORDER BY updated_at DESC
    """, (user_id,))
    
    projects = []
    for row in cur.fetchall():
        projects.append({
            "id": row[0],
            "name": row[1],
            "created_at": row[2],
            "updated_at": row[3],
            "is_public": row[4] is not None
        })
    
    con.close()
    return jsonify(projects)

@app.route("/api/3d/projects/<int:project_id>", methods=["GET"])
def get_3d_project(project_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT name, project_data, public_token 
        FROM three_d_projects 
        WHERE id=? AND user_id=?
    """, (project_id, user_id))
    
    project = cur.fetchone()
    con.close()
    
    if not project:
        return jsonify({"error": "Projekt nenalezen"}), 404
    
    return jsonify({
        "name": project[0],
        "project_data": project[1],
        "is_public": project[2] is not None
    })

@app.route("/api/3d/projects/<int:project_id>", methods=["PUT"])
def update_3d_project(project_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    project_name = data.get("name")
    project_data = data.get("project_data")

    con = db()
    cur = con.cursor()
    
    # Ověřit vlastnictví
    cur.execute("SELECT id FROM three_d_projects WHERE id=? AND user_id=?", (project_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "Projekt nenalezen"}), 404

    try:
        if project_name and project_data:
            cur.execute("""
                UPDATE three_d_projects 
                SET name=?, project_data=?, updated_at=?
                WHERE id=?
            """, (project_name, project_data, datetime.now(), project_id))
        elif project_name:
            cur.execute("""
                UPDATE three_d_projects 
                SET name=?, updated_at=?
                WHERE id=?
            """, (project_name, datetime.now(), project_id))
        elif project_data:
            cur.execute("""
                UPDATE three_d_projects 
                SET project_data=?, updated_at=?
                WHERE id=?
            """, (project_data, datetime.now(), project_id))
            
        con.commit()
        return jsonify({"message": "Projekt aktualizován"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        con.close()

@app.route("/api/3d/projects/<int:project_id>", methods=["DELETE"])
def delete_3d_project(project_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    
    # Ověřit vlastnictví
    cur.execute("SELECT id FROM three_d_projects WHERE id=? AND user_id=?", (project_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "Projekt nenalezen"}), 404

    cur.execute("DELETE FROM three_d_projects WHERE id=?", (project_id,))
    con.commit()
    con.close()
    
    return jsonify({"message": "Projekt smazán"})

@app.route("/api/3d/projects/<int:project_id>/share", methods=["POST"])
def share_3d_project(project_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    
    # Ověřit vlastnictví
    cur.execute("SELECT id FROM three_d_projects WHERE id=? AND user_id=?", (project_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "Projekt nenalezen"}), 404
    
    # Generovat public token
    public_token = str(uuid.uuid4())
    cur.execute("UPDATE three_d_projects SET public_token=? WHERE id=?", (public_token, project_id))
    con.commit()
    con.close()
    
    return jsonify({
        "message": "Projekt je nyní veřejný",
        "public_url": f"/api/3d/projects/public/{public_token}"
    })
# Přidejte nový endpoint pro získání informací o úložišti
@app.route("/api/cloud/storage/info", methods=["GET"])
def get_storage_info():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    storage_info = check_storage_limit(user_id)
    
    # Získání historie využití
    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT 
            strftime('%Y-%m', timestamp) as month,
            SUM(CASE WHEN action = 'upload' THEN file_size ELSE 0 END) as uploads,
            SUM(CASE WHEN action = 'delete' THEN file_size ELSE 0 END) as deletes,
            COUNT(*) as actions
        FROM storage_history 
        WHERE user_id = ? 
        GROUP BY strftime('%Y-%m', timestamp)
        ORDER BY month DESC
        LIMIT 6
    """, (user_id,))
    
    history = cur.fetchall()
    con.close()
    
    return jsonify({
        "storage_info": storage_info,
        "history": [
            {
                "month": row[0],
                "uploads": row[1],
                "deletes": row[2],
                "actions": row[3]
            } for row in history
        ]
    })

# Přidejte endpoint pro získání detailů o velikosti souborů podle typu
@app.route("/api/cloud/storage/breakdown", methods=["GET"])
def get_storage_breakdown():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT 
            file_type,
            COUNT(*) as file_count,
            SUM(file_size) as total_size,
            AVG(file_size) as avg_size
        FROM cloud_files 
        WHERE user_id = ? 
        GROUP BY file_type
        ORDER BY total_size DESC
    """, (user_id,))
    
    breakdown = cur.fetchall()
    con.close()
    
    return jsonify({
        "breakdown": [
            {
                "type": row[0],
                "count": row[1],
                "total_size": row[2],
                "avg_size": row[3]
            } for row in breakdown
        ]
    })


# ----------- CALCULATOR ENDPOINTS -----------

@app.route("/api/calc/python", methods=["POST"])
def calc_python():
    """Evaluate Python code safely for calculator"""
    data = request.json
    code = data.get("code", "")
    
    if not code:
        return jsonify({"error": "No code provided"}), 400
    
    # Basic security: limit length and check for dangerous imports
    if len(code) > 1000:
        return jsonify({"error": "Code too long"}), 400
    
    # Blacklist dangerous operations
    dangerous_patterns = [
        "__import__", "import ", "from ", "exec", "eval", "compile",
        "open", "file", "os.", "sys.", "subprocess", "shutil",
        "rm ", "del ", "breakpoint", "globals", "locals"
    ]
    
    for pattern in dangerous_patterns:
        if pattern in code:
            return jsonify({"error": f"Operation not allowed: {pattern}"}), 400
    
    try:
        # Create restricted globals
        safe_globals = {
            "__builtins__": {
                'abs': abs, 'round': round, 'min': min, 'max': max, 'sum': sum,
                'int': int, 'float': float, 'str': str, 'bool': bool,
                'len': len, 'range': range, 'list': list, 'tuple': tuple,
                'dict': dict, 'set': set
            },
            'math': {
                'sin': math.sin, 'cos': math.cos, 'tan': math.tan,
                'asin': math.asin, 'acos': math.acos, 'atan': math.atan,
                'atan2': math.atan2, 'sinh': math.sinh, 'cosh': math.cosh,
                'tanh': math.tanh, 'log': math.log, 'log10': math.log10,
                'log2': math.log2, 'exp': math.exp, 'sqrt': math.sqrt,
                'pow': math.pow, 'pi': math.pi, 'e': math.e,
                'ceil': math.ceil, 'floor': math.floor, 'trunc': math.trunc,
                'degrees': math.degrees, 'radians': math.radians,
                'factorial': math.factorial, 'gcd': math.gcd,
                'hypot': math.hypot, 'isclose': math.isclose
            },
            'random': {
                'random': random.random,
                'randint': random.randint,
                'uniform': random.uniform,
                'choice': random.choice,
                'shuffle': random.shuffle,
                'sample': random.sample,
                'seed': random.seed
            },
            'statistics': {
                'mean': statistics.mean,
                'median': statistics.median,
                'mode': statistics.mode,
                'stdev': statistics.stdev,
                'variance': statistics.variance
            }
        }
        
        # Evaluate the code
        result = eval(code, safe_globals, {})
        
        # Convert result to string
        if result is None:
            result_str = "None"
        elif isinstance(result, (int, float)):
            result_str = str(result)
        elif isinstance(result, (list, tuple, dict, set)):
            result_str = str(result)
        else:
            result_str = str(result)
        
        return jsonify({"result": result_str})
        
    except SyntaxError as e:
        return jsonify({"error": f"Syntax error: {str(e)}"}), 400
    except NameError as e:
        return jsonify({"error": f"Name error: {str(e)}"}), 400
    except TypeError as e:
        return jsonify({"error": f"Type error: {str(e)}"}), 400
    except ValueError as e:
        return jsonify({"error": f"Value error: {str(e)}"}), 400
    except ZeroDivisionError as e:
        return jsonify({"error": "Division by zero"}), 400
    except Exception as e:
        return jsonify({"error": f"Calculation error: {str(e)}"}), 400


@app.route("/api/calc/history", methods=["GET"])
def get_calc_history():
    """Get calculator history for user"""
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    
    # Create table if not exists
    cur.execute("""
        CREATE TABLE IF NOT EXISTS calculator_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            expression TEXT NOT NULL,
            result TEXT NOT NULL,
            mode TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # Get user's history
    cur.execute("""
        SELECT expression, result, mode, timestamp 
        FROM calculator_history 
        WHERE user_id=? 
        ORDER BY timestamp DESC 
        LIMIT 50
    """, (user_id,))
    
    history = []
    for row in cur.fetchall():
        history.append({
            "expression": row[0],
            "result": row[1],
            "mode": row[2],
            "timestamp": row[3]
        })
    
    con.close()
    return jsonify(history)

# ----------- CHANGE PASSWORD -----------
@app.route("/api/change-password", methods=["POST"])
def change_password():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"error": "Missing fields"}), 400

    con = db()
    cur = con.cursor()
    
    # Získání aktuálního hesla
    cur.execute("SELECT password_hash FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    
    if not row:
        con.close()
        return jsonify({"error": "User not found"}), 404

    stored_hash = row[0]
    
    # Kontrola, zda je uživatel přihlášen přes Google
    if stored_hash == "GOOGLE_USER":
        con.close()
        return jsonify({"error": "Google users cannot change password via this method"}), 400
    
    # Kontrola starého hesla
    if not bcrypt.checkpw(old_password.encode(), stored_hash.encode()):
        con.close()
        return jsonify({"error": "Current password is incorrect"}), 403

    # Hashování nového hesla
    new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    
    # Aktualizace hesla v databázi
    cur.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user_id))
    con.commit()
    con.close()

    return jsonify({"message": "Password changed successfully"})

# ----------- LOGOUT -----------
@app.route("/api/logout", methods=["POST"])
def logout():
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE users SET token=NULL WHERE id=?", (user_id,))
    con.commit()
    con.close()

    return jsonify({"message": "Logged out successfully"})


@app.route("/api/calc/history", methods=["POST"])
def save_calc_history():
    """Save calculator history entry"""
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    expression = data.get("expression", "")
    result = data.get("result", "")
    mode = data.get("mode", "basic")
    
    if not expression or not result:
        return jsonify({"error": "Missing data"}), 400
    
    con = db()
    cur = con.cursor()
    
    cur.execute("""
        INSERT INTO calculator_history (user_id, expression, result, mode)
        VALUES (?, ?, ?, ?)
    """, (user_id, expression, result, mode))
    
    con.commit()
    con.close()
    
    return jsonify({"message": "History saved"})


@app.route("/api/calc/history/clear", methods=["POST"])
def clear_calc_history():
    """Clear calculator history for user"""
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    
    cur.execute("DELETE FROM calculator_history WHERE user_id=?", (user_id,))
    
    con.commit()
    con.close()
    
    return jsonify({"message": "History cleared"})

@app.route("/api/3d/projects/<int:project_id>/unshare", methods=["POST"])
def unshare_3d_project(project_id):
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    con = db()
    cur = con.cursor()
    
    # Ověřit vlastnictví
    cur.execute("SELECT id FROM three_d_projects WHERE id=? AND user_id=?", (project_id, user_id))
    if not cur.fetchone():
        con.close()
        return jsonify({"error": "Projekt nenalezen"}), 404
    
    cur.execute("UPDATE three_d_projects SET public_token=NULL WHERE id=?", (project_id,))
    con.commit()
    con.close()
    
    return jsonify({"message": "Projekt je nyní soukromý"})

@app.route("/api/3d/projects/public/<token>", methods=["GET"])
def get_public_3d_project(token):
    con = db()
    cur = con.cursor()
    cur.execute("""
        SELECT id, name, project_data, user_id 
        FROM three_d_projects 
        WHERE public_token=?
    """, (token,))
    
    project = cur.fetchone()
    con.close()
    
    if not project:
        return jsonify({"error": "Projekt nenalezen"}), 404
    
    return jsonify({
        "id": project[0],
        "name": project[1],
        "project_data": project[2],
        "owner_id": project[3]
    })

# SocketIO events pro 3D spolupráci
@socketio.on('3d_operation')
def handle_3d_operation(data):
    try:
        public_token = data.get('public_token')
        operation = data.get('operation')
        username = data.get('username', 'Anonymous')
        
        # Odeslání operace všem ostatním v room
        emit('3d_update', {
            'operation': operation,
            'username': username,
            'socket_id': request.sid
        }, room=public_token, include_self=False)
        
    except Exception as e:
        print(f"Error in 3d_operation: {e}")

# Přidejte funkci pro kontrolu úložiště
def check_storage_limit(user_id, additional_size=0):
    """Zkontroluje, zda uživatel nepřekračuje limit úložiště"""
    con = db()
    cur = con.cursor()
    
    # Získání aktuálního využití
    cur.execute("""
        SELECT COALESCE(SUM(file_size), 0) 
        FROM cloud_files 
        WHERE user_id=?
    """, (user_id,))
    
    current_usage = cur.fetchone()[0] or 0
    
    # Získání limitu
    cur.execute("""
        SELECT max_storage_bytes 
        FROM user_storage_limits 
        WHERE user_id=?
    """, (user_id,))
    
    limit_row = cur.fetchone()
    if limit_row:
        max_storage = limit_row[0]
    else:
        # Výchozí limit: 170,000,000 bytů (~162 MB)
        max_storage = 170000000
        cur.execute("""
            INSERT OR REPLACE INTO user_storage_limits (user_id, max_storage_bytes)
            VALUES (?, ?)
        """, (user_id, max_storage))
        con.commit()
    
    con.close()
    
    # Výpočet procenta využití
    usage_percentage = (current_usage / max_storage) * 100 if max_storage > 0 else 0
    
    # Kontrola překročení limitu
    if current_usage + additional_size > max_storage:
        return {
            "allowed": False,
            "current_usage": current_usage,
            "max_storage": max_storage,
            "usage_percentage": usage_percentage,
            "available": max_storage - current_usage
        }
    else:
        return {
            "allowed": True,
            "current_usage": current_usage,
            "max_storage": max_storage,
            "usage_percentage": usage_percentage,
            "available": max_storage - current_usage - additional_size
        }

def update_storage_usage(user_id):
    """Aktualizuje záznam o využití úložiště"""
    con = db()
    cur = con.cursor()
    
    cur.execute("""
        SELECT COALESCE(SUM(file_size), 0) 
        FROM cloud_files 
        WHERE user_id=?
    """, (user_id,))
    
    current_usage = cur.fetchone()[0] or 0
    
    cur.execute("""
        INSERT OR REPLACE INTO user_storage_limits 
        (user_id, used_storage_bytes, last_updated)
        VALUES (?, ?, CURRENT_TIMESTAMP)
    """, (user_id, current_usage))
    
    con.commit()
    con.close()

# ----------- IMAGE PREVIEW ENDPOINTS -----------

@app.route("/api/cloud/preview/<int:file_id>", methods=["GET"])
def cloud_get_preview(file_id):
    """Endpoint pro získání náhledu obrázku"""
    token = request.headers.get("Authorization")
    user_id = get_user_id_from_token(token)
    
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    con = db()
    cur = con.cursor()
    cur.execute("SELECT user_id, stored_filename, original_filename, file_type FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    file_data = cur.fetchone()
    con.close()
    
    if not file_data:
        return jsonify({"error": "File not found"}), 404
    
    user_id, stored_filename, original_filename, file_type = file_data
    
    # Kontrola, zda je soubor obrázek
    if file_type not in ['image', 'vector']:
        return jsonify({"error": "File is not an image"}), 400
    
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    file_path = os.path.join(user_dir, stored_filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    return send_file(file_path, as_attachment=False)

@app.route("/api/cloud/preview/public/<token>", methods=["GET"])
def cloud_get_public_preview(token):
    """Endpoint pro získání veřejného náhledu obrázku"""
    con = db()
    cur = con.cursor()
    cur.execute("SELECT user_id, stored_filename, original_filename, file_type FROM cloud_files WHERE public_token=?", (token,))
    file_data = cur.fetchone()
    con.close()
    
    if not file_data:
        return jsonify({"error": "File not found"}), 404
    
    user_id, stored_filename, original_filename, file_type = file_data
    
    # Kontrola, zda je soubor obrázek
    if file_type not in ['image', 'vector']:
        return jsonify({"error": "File is not an image"}), 400
    
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
    file_path = os.path.join(user_dir, stored_filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    return send_file(file_path, as_attachment=False)

# ---- GOOGLE LOGIN ----
@app.route("/auth/google")
def auth_google():
    flow.redirect_uri = "https://upperoffice.site/auth/google/callback"
    authorization_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(authorization_url)


@app.route("/auth/google/callback")
def auth_google_callback():
    flow.redirect_uri = "https://upperoffice.site/auth/google/callback"
    flow.fetch_token(authorization_response=request.url)

    credentials = flow.credentials
    google_token = credentials.id_token

    user_info = id_token.verify_oauth2_token(
        google_token,
        Request(),
        GOOGLE_CLIENT_ID
    )

    email = user_info["email"]
    user_id = get_or_create_google_user(email)

    token = generate_token()

    con = db()
    cur = con.cursor()
    cur.execute("UPDATE users SET token=? WHERE id=?", (token, user_id))
    con.commit()
    con.close()

    return redirect(f"/google_redirect.html?token={token}")







# ----------- STATIC FILES -----------
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_static(path):
    try:
        return send_file(path)
    except FileNotFoundError:
        return {"error": "Page not found"}, 404 
        
# ----------- GLOBAL 404 HANDLER -----------
@app.errorhandler(404)
def page_not_found(e):
    return {"error": "Page not found"}, 404


# ----------- START -----------
if __name__ == "__main__":
    # Initialize database with cloud_files table
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cloud_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            upload_date DATETIME NOT NULL,
            public_token TEXT UNIQUE,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS collaboration_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_id INTEGER NOT NULL,
        public_token TEXT NOT NULL,
        share_mode TEXT NOT NULL DEFAULT 'read_only',
        owner_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (file_id) REFERENCES cloud_files (id),
        FOREIGN KEY (owner_id) REFERENCES users (id)
        )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS active_collaborators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        socket_id TEXT NOT NULL,
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES collaboration_sessions (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ide_projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        files_content TEXT,
        folder_structure TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS three_d_projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        project_data TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        public_token TEXT UNIQUE,
        FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_storage_limits (
        user_id INTEGER PRIMARY KEY,
        max_storage_bytes INTEGER DEFAULT 170000000, -- 162 MB v bytech
        used_storage_bytes INTEGER DEFAULT 0,
        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS storage_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL, -- 'upload' nebo 'delete'
        file_id INTEGER,
        file_size INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        FOREIGN KEY (file_id) REFERENCES cloud_files (id)
    )
    """)


    con.commit()
    con.close()
    
    app.run(host="0.0.0.0", port=1234)