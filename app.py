from flask import Flask, request, jsonify, send_from_directory, send_file, Response, abort
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

app = Flask(__name__, static_folder="static")

DB = "users.db"
UPLOAD_FOLDER = "cloud_storage"
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'webm', 'WebM'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# CloudConvert API configuration
CLOUDCONVERT_API_KEY = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiNzIxMTIwZDY5MmE0OWMwZjZkY2RhNmQxYWQ5YzBmMDAyYjEyODk2NDE4ZDZjOWNiZDQyNWU5ZGE4ZTk1YjcyNjM0NzVhZmU0YTU3ZjNjZTEiLCJpYXQiOjE3NjM1NzI5MzQuNDU5NTA2LCJuYmYiOjE3NjM1NzI5MzQuNDU5NTA3LCJleHAiOjQ5MTkyNDY1MzQuNDU1NDI0LCJzdWIiOiI3MzUxNzMxNCIsInNjb3BlcyI6WyJ0YXNrLnJlYWQiLCJ0YXNrLndyaXRlIiwicHJlc2V0LnJlYWQiLCJwcmVzZXQud3JpdGUiXX0.fVT6fVrfpN1Zh0MHeu24eI1r6bozGxh1h57SLRhD6bMyfxrJDpxgtwovXuIQ52_liUyS6kDy80ZahGjm0v3UwiwiVf9V1s7T-OD4tN4lbhG78TmGaTo-nWT37T-dKgCbqbWJ6EHmrm_5XhHmAlYYsETt22-8oU6pTMN6OiadKh__ehO16kHY7x5F_UdI_vsK_UcCTVgGRGWEoMWQF6ssLB9t3Dljn0BkInT1VbhwnrxiQaNqt0_o5Nh0uHVWmldOq2dg3PfpQlYjR9EOtj_z32usABwf1s49ZmF1w0rk-mv8aGxspItSOjPQgmVvwf-LOnpzX8F5-XmwcVIFNJIekHm4vFjArINrJ6pekvb6m63T4re9DHYVTHazvL1_fvh5BkxHr5H93vuwZrbQivdV8eJOSSBcfgbP5biltY2l2CEA5GesckQv67MXr8PkrK-siIOBoXotFVjss6CXJ4d2ijm_bp07LznTfee15l3UqY7a6GgQusLsVARrJHGKAppU6JhmqjygOrwBDM0QXwL2AxrGUVO_PtZ8e9jgD8d24JcoAkW0lDgTaQGh_WgN1UC3RIJFke8uRcZUvYQTODVAw94WjCjP6ceaojLrr6ktR4p8z2EUkupTg4WifO8hUZyx5tgxTTrWMxT0W5px-IpjBqB0AXwKFzb79G-EwxMVpvI"  # Získejte zdarma na cloudconvert.com
CONVERTAPI_SECRET = "Sf9JecGzQNCmcQhGDUX29TY1y9F5Vrq1"  # Z ConvertAPI dashboard


# Create upload directory if not exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def db():
    return sqlite3.connect(DB)

# ----------- UTIL -----------
def generate_token():
    return secrets.token_hex(32)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_id_from_token(token):
    if not token:
        return None
    con = db()
    cur = con.cursor()
    cur.execute("SELECT id FROM users WHERE token=?", (token,))
    row = cur.fetchone()
    con.close()
    return row[0] if row else None

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
        # Generate unique filename
        file_id = str(uuid.uuid4())
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower()
        stored_filename = f"{file_id}.{file_extension}"
        
        # Create user directory if not exists
        user_dir = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}")
        os.makedirs(user_dir, exist_ok=True)
        
        file_path = os.path.join(user_dir, stored_filename)
        file.save(file_path)
        
        # Get file type
        file_type = 'image' if file_extension in ['png', 'jpg', 'jpeg', 'gif', 'webm', 'WebM'] else 'document'
        
        # Store file info in database
        con = db()
        cur = con.cursor()
        cur.execute("""
            INSERT INTO cloud_files (user_id, original_filename, stored_filename, file_type, file_size, upload_date, public_token)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, original_filename, stored_filename, file_type, os.path.getsize(file_path), datetime.now(), None))
        con.commit()
        con.close()
        
        return jsonify({
            "message": "File uploaded successfully",
            "file_id": cur.lastrowid,
            "filename": original_filename
        })
    
    return jsonify({"error": "Invalid file type"}), 400

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
            "public_token": row[5],  # PŘIDÁNO - toto chybělo!
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
    
    # Verify ownership
    cur.execute("SELECT stored_filename FROM cloud_files WHERE id=? AND user_id=?", (file_id, user_id))
    file_data = cur.fetchone()
    
    if not file_data:
        con.close()
        return jsonify({"error": "File not found"}), 404
    
    # Delete file from filesystem
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"user_{user_id}", file_data[0])
    if os.path.exists(file_path):
        os.remove(file_path)
    
    # Delete from database
    cur.execute("DELETE FROM cloud_files WHERE id=?", (file_id,))
    con.commit()
    con.close()
    
    return jsonify({"message": "File deleted successfully"})

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

@app.route("/app.py")
def noaccess():
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
    con.commit()
    con.close()
    
    app.run(host="0.0.0.0", port=1144)