from flask import Flask, request, jsonify, send_from_directory, send_file, Response, abort
import sqlite3
import bcrypt
import secrets
import os
import subprocess

app = Flask(__name__, static_folder="static")

DB = "users.db"

def db():
    return sqlite3.connect(DB)

# ----------- UTIL -----------
def generate_token():
    return secrets.token_hex(32)

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
    app.run(host="0.0.0.0", port=1144)
