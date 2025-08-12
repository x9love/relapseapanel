import sqlite3
import datetime
import secrets
import requests
import os
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))  # Use environment variable for secret key

# Discord Webhook URL from environment variable
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL')

# Database setup
def init_db():
    db_path = os.environ.get('DB_PATH', 'keys.db')  # Use environment variable for DB path
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys
                 (key TEXT PRIMARY KEY, expiration DATE, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS admins
                 (username TEXT PRIMARY KEY, password_hash TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS settings
                 (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                 (api_key TEXT PRIMARY KEY, status TEXT, created_at DATE)''')
    conn.commit()
    conn.close()

# Add default admin if not exists
def add_default_admin():
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT * FROM admins WHERE username='admin'")
    if not c.fetchone():
        password_hash = generate_password_hash('password')
        c.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", ('admin', password_hash))
        conn.commit()
    conn.close()

# Initialize settings
def init_settings():
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT * FROM settings WHERE key='loader_version'")
    if not c.fetchone():
        c.execute("INSERT INTO settings (key, value) VALUES ('loader_version', '1.0')")
        conn.commit()
    conn.close()

init_db()
add_default_admin()
init_settings()

# Function to get geolocation data from IP
def get_geolocation(ip):
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        if response.status_code == 200:
            data = response.json()
            return {
                'city': data.get('city', 'Unknown'),
                'region': data.get('region', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'ip': ip
            }
        return {'city': 'Unknown', 'region': 'Unknown', 'country': 'Unknown', 'ip': ip}
    except Exception as e:
        print(f"Failed to get geolocation: {e}")
        return {'city': 'Unknown', 'region': 'Unknown', 'country': 'Unknown', 'ip': ip}

# Function to send log to Discord webhook
def send_discord_log(message):
    if not DISCORD_WEBHOOK_URL:
        print("Discord webhook URL not configured")
        return
    data = {"content": message}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=data)
    except Exception as e:
        print(f"Failed to send Discord log: {e}")

# Function to validate API key
def validate_api_key(api_key):
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT status FROM api_keys WHERE api_key=?", (api_key,))
    result = c.fetchone()
    conn.close()
    return result and result[0] == 'active'

# API Endpoints

@app.route('/api/create_key', methods=['POST'])
def create_key():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not (session.get('logged_in') or validate_api_key(api_key)):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    expiration = data.get('expiration')
    count = data.get('count', 1)
    if not expiration:
        return jsonify({'error': 'Expiration date required'}), 400
    if count < 1:
        return jsonify({'error': 'Count must be at least 1'}), 400
    
    try:
        expiration_date = datetime.datetime.strptime(expiration, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    keys_created = []
    for _ in range(count):
        key = secrets.token_hex(16)
        c.execute("INSERT INTO keys (key, expiration, status) VALUES (?, ?, ?)", (key, expiration_date, 'active'))
        keys_created.append(key)
    conn.commit()
    conn.close()
    
    log_message = f"New key(s) created: {', '.join(keys_created)} with expiration {expiration}"
    send_discord_log(log_message)
    
    return jsonify({'keys': keys_created, 'expiration': expiration, 'status': 'active'})

@app.route('/api/check_key', methods=['GET'])
def check_key():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not (session.get('logged_in') or validate_api_key(api_key)):
        return jsonify({'error': 'Unauthorized'}), 401
    
    key = request.args.get('key')
    if not key:
        return jsonify({'error': 'Key required'}), 400
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT expiration, status FROM keys WHERE key=?", (key,))
    result = c.fetchone()
    conn.close()
    
    if not result:
        return jsonify({'error': 'Key not found'}), 404
    
    expiration, status = result
    is_valid = status == 'active' and datetime.date.today() <= datetime.date.fromisoformat(expiration)
    
    client_ip = request.remote_addr
    geo_data = get_geolocation(client_ip)
    geo_info = f"IP: {geo_data['ip']}, City: {geo_data['city']}, Region: {geo_data['region']}, Country: {geo_data['country']}"
    send_discord_log(f"Key checked: {key}, Valid: {is_valid}, From: {geo_info}")
    
    return jsonify({
        'key': key,
        'expiration': expiration,
        'status': status,
        'valid': is_valid
    })

@app.route('/api/deactivate_key', methods=['POST'])
def deactivate_key():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not (session.get('logged_in') or validate_api_key(api_key)):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    key = data.get('key')
    if not key:
        return jsonify({'error': 'Key required'}), 400
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("UPDATE keys SET status='inactive' WHERE key=?", (key,))
    conn.commit()
    conn.close()
    
    log_message = f"Key deactivated: {key}"
    send_discord_log(log_message)
    
    return jsonify({'message': 'Key deactivated'})

@app.route('/api/get_loader_version', methods=['GET'])
def get_loader_version():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not (session.get('logged_in') or validate_api_key(api_key)):
        return jsonify({'error': 'Unauthorized'}), 401
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key='loader_version'")
    result = c.fetchone()
    conn.close()
    
    version = result[0] if result else '1.0'
    return jsonify({'version': version})

@app.route('/api/update_loader_version', methods=['POST'])
def update_loader_version():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not (session.get('logged_in') or validate_api_key(api_key)):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    version = data.get('version')
    if not version:
        return jsonify({'error': 'Version required'}), 400
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("REPLACE INTO settings (key, value) VALUES ('loader_version', ?)", (version,))
    conn.commit()
    conn.close()
    
    log_message = f"Loader version updated to {version}"
    send_discord_log(log_message)
    
    return jsonify({'message': 'Loader version updated'})

@app.route('/api/add_admin', methods=['POST'])
def add_admin():
    api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
    if not (session.get('logged_in') and session['username'] == 'admin' or validate_api_key(api_key)):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    password_hash = generate_password_hash(password)
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Username already exists'}), 400
    conn.close()
    
    log_message = f"New admin added: {username}"
    send_discord_log(log_message)
    
    return jsonify({'message': 'Admin added'})

@app.route('/api/generate_api_key', methods=['POST'])
def generate_api_key():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    api_key = secrets.token_hex(16)
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("INSERT INTO api_keys (api_key, status, created_at) VALUES (?, ?, ?)",
              (api_key, 'active', datetime.date.today().isoformat()))
    conn.commit()
    conn.close()
    
    send_discord_log(f"New API key generated: {api_key}")
    return jsonify({'api_key': api_key})

@app.route('/api/deactivate_api_key', methods=['POST'])
def deactivate_api_key():
    if not session.get('logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    api_key = data.get('api_key')
    if not api_key:
        return jsonify({'error': 'API key required'}), 400
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("UPDATE api_keys SET status='inactive' WHERE api_key=?", (api_key,))
    conn.commit()
    conn.close()
    
    send_discord_log(f"API key deactivated: {api_key}")
    return jsonify({'message': 'API key deactivated'})

# Admin Panel Routes

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        client_ip = request.remote_addr
        geo_data = get_geolocation(client_ip)
        geo_info = f"IP: {geo_data['ip']}, City: {geo_data['city']}, Region: {geo_data['region']}, Country: {geo_data['country']}"
        
        db_path = os.environ.get('DB_PATH', 'keys.db')
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT password_hash FROM admins WHERE username=?", (username,))
        result = c.fetchone()
        conn.close()
        
        if result and check_password_hash(result[0], password):
            session['logged_in'] = True
            session['username'] = username
            send_discord_log(f"Admin logged in: {username} from {geo_info}")
            return redirect(url_for('admin_panel'))
        else:
            error_message = f"Failed login attempt: Username '{username}', Password '****' from {geo_info}"
            send_discord_log(error_message)
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Admin Login</title>
                <link href="https://fonts.googleapis.com/css2?family=Space+Mono&display=swap" rel="stylesheet">
                <style>
                    body {
                        background: #000;
                        color: #fff;
                        font-family: 'Space Mono', monospace;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        overflow: hidden;
                    }
                    .login-card {
                        background: #1a1a1a;
                        padding: 40px;
                        border-radius: 15px;
                        text-align: center;
                        width: 350px;
                        box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
                        animation: fadeIn 1.5s ease-in-out;
                    }
                    @keyframes fadeIn {
                        from { opacity: 0; transform: scale(0.9); }
                        to { opacity: 1; transform: scale(1); }
                    }
                    .login-card h2 {
                        margin-bottom: 35px;
                        font-size: 28px;
                        letter-spacing: 2px;
                    }
                    .login-card .form-group {
                        margin-bottom: 20px;
                    }
                    .login-card input {
                        width: 100%;
                        padding: 15px;
                        margin: 8px 0;
                        background: #2a2a2a;
                        border: none;
                        color: #fff;
                        border-radius: 8px;
                        font-family: 'Space Mono', monospace;
                        text-align: center;
                        display: block;
                        box-sizing: border-box;
                        transition: background 0.3s;
                    }
                    .login-card input:focus {
                        background: #3a3a3a;
                        outline: none;
                    }
                    .login-card button {
                        width: 100%;
                        padding: 15px;
                        background: #666;
                        border: none;
                        color: #fff;
                        border-radius: 8px;
                        cursor: pointer;
                        font-family: 'Space Mono', monospace;
                        margin-top: 20px;
                        transition: background 0.3s;
                    }
                    .login-card button:hover {
                        background: #888;
                    }
                    .login-card p {
                        color: #ff4444;
                        margin-top: 15px;
                        font-size: 16px;
                    }
                    .shapes {
                        position: fixed;
                        top: 0;
                        left: 0;
                        width: 100%;
                        height: 100%;
                        z-index: -1;
                    }
                    .shapes div {
                        position: absolute;
                        background: #fff;
                        opacity: 0.15;
                        animation: float 20s infinite;
                    }
                    .shapes .triangle {
                        width: 0;
                        height: 0;
                        border-left: 25px solid transparent;
                        border-right: 25px solid transparent;
                        border-bottom: 50px solid;
                    }
                    .shapes .square {
                        width: 25px;
                        height: 25px;
                    }
                    @keyframes float {
                        0% { transform: translateY(0) rotate(0deg); }
                        50% { transform: translateY(-60px) rotate(180deg); }
                        100% { transform: translateY(0) rotate(360deg); }
                    }
                </style>
            </head>
            <body>
                <div class="shapes">
                    <div class="triangle" style="left: 15%; top: 25%; animation-delay: 0s;"></div>
                    <div class="square" style="left: 35%; top: 45%; animation-delay: 5s;"></div>
                    <div class="triangle" style="left: 55%; top: 65%; animation-delay: 10s;"></div>
                    <div class="square" style="left: 75%; top: 35%; animation-delay: 15s;"></div>
                </div>
                <div class="login-card">
                    <h2>Admin Login</h2>
                    <p>Invalid credentials</p>
                    <form method="post">
                        <div class="form-group">
                            <input type="text" name="username" placeholder="Username" required>
                        </div>
                        <div class="form-group">
                            <input type="password" name="password" placeholder="Password" required>
                        </div>
                        <button type="submit">Enter</button>
                    </form>
                </div>
            </body>
            </html>
            ''')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login</title>
        <link href="https://fonts.googleapis.com/css2?family=Space+Mono&display=swap" rel="stylesheet">
        <style>
            body {
                background: #000;
                color: #fff;
                font-family: 'Space Mono', monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                overflow: hidden;
            }
            .login-card {
                background: #1a1a1a;
                padding: 40px;
                border-radius: 15px;
                text-align: center;
                width: 350px;
                box-shadow: 0 0 20px rgba(255, 255, 255, 0.1);
                animation: fadeIn 1.5s ease-in-out;
            }
            @keyframes fadeIn {
                from { opacity: 0; transform: scale(0.9); }
                to { opacity: 1; transform: scale(1); }
            }
            .login-card h2 {
                margin-bottom: 35px;
                font-size: 28px;
                letter-spacing: 2px;
            }
            .login-card .form-group {
                margin-bottom: 20px;
            }
            .login-card input {
                width: 100%;
                padding: 15px;
                margin: 8px 0;
                background: #2a2a2a;
                border: none;
                color: #fff;
                border-radius: 8px;
                font-family: 'Space Mono', monospace;
                text-align: center;
                display: block;
                box-sizing: border-box;
                transition: background 0.3s;
            }
            .login-card input:focus {
                background: #3a3a3a;
                outline: none;
            }
            .login-card button {
                width: 100%;
                padding: 15px;
                background: #666;
                border: none;
                color: #fff;
                border-radius: 8px;
                cursor: pointer;
                font-family: 'Space Mono', monospace;
                margin-top: 20px;
                transition: background 0.3s;
            }
            .login-card button:hover {
                background: #888;
            }
            .shapes {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
            }
            .shapes div {
                position: absolute;
                background: #fff;
                opacity: 0.15;
                animation: float 20s infinite;
            }
            .shapes .triangle {
                width: 0;
                height: 0;
                border-left: 25px solid transparent;
                border-right: 25px solid transparent;
                border-bottom: 50px solid;
            }
            .shapes .square {
                width: 25px;
                height: 25px;
            }
            @keyframes float {
                0% { transform: translateY(0) rotate(0deg); }
                50% { transform: translateY(-60px) rotate(180deg); }
                100% { transform: translateY(0) rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="shapes">
            <div class="triangle" style="left: 15%; top: 25%; animation-delay: 0s;"></div>
            <div class="square" style="left: 35%; top: 45%; animation-delay: 5s;"></div>
            <div class="triangle" style="left: 55%; top: 65%; animation-delay: 10s;"></div>
            <div class="square" style="left: 75%; top: 35%; animation-delay: 15s;"></div>
        </div>
        <div class="login-card">
            <h2>Admin Login</h2>
            <form method="post">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Username" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Password" required>
                </div>
                <button type="submit">Enter</button>
            </form>
        </div>
    </body>
    </html>
    ''')

@app.route('/admin', methods=['GET'])
def admin_panel():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    db_path = os.environ.get('DB_PATH', 'keys.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT key, expiration, status FROM keys")
    keys = c.fetchall()
    c.execute("SELECT api_key, status, created_at FROM api_keys")
    api_keys = c.fetchall()
    conn.close()
    
    keys_html = ''
    for k in keys:
        keys_html += f'''
        <tr>
            <td>{k[0]}</td>
            <td>{k[1]}</td>
            <td><span style="color: {'#00ff00' if k[2] == 'active' else '#ff0000'};">{k[2]}</span></td>
            <td><button onclick="deactivateKey('{k[0]}')">Deactivate</button></td>
        </tr>
        '''
    
    api_keys_html = ''
    for ak in api_keys:
        api_keys_html += f'''
        <tr>
            <td>{ak[0]}</td>
            <td>{ak[2]}</td>
            <td><span style="color: {'#00ff00' if ak[1] == 'active' else '#ff0000'};">{ak[1]}</span></td>
            <td><button onclick="deactivateApiKey('{ak[0]}')">Deactivate</button></td>
        </tr>
        '''
    
    is_super_admin = session['username'] == 'admin'
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <link href="https://fonts.googleapis.com/css2?family=Space+Mono&display=swap" rel="stylesheet">
        <style>
            body {
                background: #000;
                color: #fff;
                font-family: 'Space Mono', monospace;
                margin: 0;
                overflow: hidden;
            }
            .container {
                max-width: 1200px;
                margin: 30px auto;
                padding: 20px;
            }
            .card {
                background: #1a1a1a;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 15px rgba(255, 255, 255, 0.1);
            }
            .tabs button {
                padding: 10px 20px;
                background: #333;
                border: none;
                color: #fff;
                cursor: pointer;
                margin-right: 5px;
            }
            .tabs button:hover {
                background: #555;
            }
            .tab-content {
                margin-top: 20px;
            }
            h2 {
                margin-top: 0;
                font-size: 24px;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            td {
                padding: 12px;
                border-bottom: 1px solid #333;
                text-align: center;
            }
            button {
                padding: 8px 15px;
                background: #555;
                border: none;
                color: #fff;
                border-radius: 5px;
                cursor: pointer;
                font-family: 'Space Mono', monospace;
            }
            button:hover {
                background: #777;
            }
            input {
                padding: 12px;
                margin: 10px 0;
                background: #333;
                border: none;
                color: #fff;
                border-radius: 5px;
                font-family: 'Space Mono', monospace;
                text-align: center;
                width: 200px;
            }
            a {
                color: #fff;
                text-decoration: underline;
                margin-bottom: 20px;
                display: block;
            }
            #status, #status_settings, #status_admins, #status_api_keys {
                color: #00ff00;
                margin: 10px 0;
                text-align: center;
            }
            .shapes {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -1;
            }
            .shapes div {
                position: absolute;
                background: #fff;
                opacity: 0.1;
                animation: float 15s infinite;
            }
            .shapes .triangle {
                width: 0;
                height: 0;
                border-left: 20px solid transparent;
                border-right: 20px solid transparent;
                border-bottom: 40px solid;
            }
            .shapes .square {
                width: 20px;
                height: 20px;
            }
            @keyframes float {
                0% { transform: translateY(0) rotate(0deg); }
                50% { transform: translateY(-50px) rotate(180deg); }
                100% { transform: translateY(0) rotate(360deg); }
            }
        </style>
        <script>
            function openTab(tabName) {
                var tabs = document.getElementsByClassName("tab-content");
                for (var i = 0; i < tabs.length; i++) {
                    tabs[i].style.display = "none";
                }
                document.getElementById(tabName).style.display = "block";
            }

            async function createKey() {
                const expiration = document.getElementById('expiration').value;
                const count = document.getElementById('count').value;
                const response = await fetch('/api/create_key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ expiration: expiration, count: parseInt(count) })
                });
                const result = await response.json();
                const statusDiv = document.getElementById('status');
                if (response.ok) {
                    statusDiv.innerText = `Keys created: ${result.keys.join(', ')}`;
                    location.reload();
                } else {
                    statusDiv.innerText = `Error: ${result.error}`;
                }
            }

            async function deactivateKey(key) {
                const response = await fetch('/api/deactivate_key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: key })
                });
                const result = await response.json();
                const statusDiv = document.getElementById('status');
                if (response.ok) {
                    statusDiv.innerText = 'Key deactivated';
                    location.reload();
                } else {
                    statusDiv.innerText = `Error: ${result.error}`;
                }
            }

            async function updateLoaderVersion() {
                const version = document.getElementById('loader_version').value;
                const response = await fetch('/api/update_loader_version', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ version: version })
                });
                const result = await response.json();
                const statusDiv = document.getElementById('status_settings');
                if (response.ok) {
                    statusDiv.innerText = 'Loader version updated';
                } else {
                    statusDiv.innerText = `Error: ${result.error}`;
                }
            }

            async function addAdmin() {
                const username = document.getElementById('new_username').value;
                const password = document.getElementById('new_password').value;
                const response = await fetch('/api/add_admin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: username, password: password })
                });
                const result = await response.json();
                const statusDiv = document.getElementById('status_admins');
                if (response.ok) {
                    statusDiv.innerText = 'Admin added';
                } else {
                    statusDiv.innerText = `Error: ${result.error}`;
                }
            }

            async function generateApiKey() {
                const response = await fetch('/api/generate_api_key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' }
                });
                const result = await response.json();
                const statusDiv = document.getElementById('status_api_keys');
                if (response.ok) {
                    statusDiv.innerText = `API Key generated: ${result.api_key}`;
                    location.reload();
                } else {
                    statusDiv.innerText = `Error: ${result.error}`;
                }
            }

            async function deactivateApiKey(apiKey) {
                const response = await fetch('/api/deactivate_api_key', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ api_key: apiKey })
                });
                const result = await response.json();
                const statusDiv = document.getElementById('status_api_keys');
                if (response.ok) {
                    statusDiv.innerText = 'API Key deactivated';
                    location.reload();
                } else {
                    statusDiv.innerText = `Error: ${result.error}`;
                }
            }

            window.onload = function() {
                fetch('/api/get_loader_version')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('loader_version').value = data.version;
                });
                openTab('keys');
            }
        </script>
    </head>
    <body>
        <div class="shapes">
            <div class="triangle" style="left: 10%; top: 20%; animation-delay: 0s;"></div>
            <div class="square" style="left: 30%; top: 40%; animation-delay: 2s;"></div>
            <div class="triangle" style="left: 50%; top: 60%; animation-delay: 4s;"></div>
            <div class="square" style="left: 70%; top: 30%; animation-delay: 6s;"></div>
        </div>
        <div class="container">
            <div class="card">
                <h2>Admin Panel</h2>
                <p>Welcome, {{ session['username'] }}</p>
                <a href="/admin/logout">Logout</a>
                <div class="tabs">
                    <button onclick="openTab('keys')">Key Management</button>
                    <button onclick="openTab('settings')">Settings</button>
                    <button onclick="openTab('api_keys')">API Keys</button>
                    {% if is_super_admin %}
                    <button onclick="openTab('admins')">Admins</button>
                    {% endif %}
                </div>
                <div id="keys" class="tab-content">
                    <h3>Keys</h3>
                    <table>
                        <tr>
                            <td>Key</td>
                            <td>Expiration</td>
                            <td>Status</td>
                            <td>Action</td>
                        </tr>
                        {{ keys_html|safe }}
                    </table>
                    <h3>Create New Key(s)</h3>
                    <input type="text" id="expiration" placeholder="Expiration (YYYY-MM-DD)">
                    <input type="number" id="count" value="1" min="1" style="width: 100px;">
                    <button onclick="createKey()">Create</button>
                    <div id="status"></div>
                </div>
                <div id="settings" class="tab-content" style="display:none;">
                    <h3>Loader Version</h3>
                    <input type="text" id="loader_version" placeholder="Version">
                    <button onclick="updateLoaderVersion()">Update</button>
                    <div id="status_settings" style="color: #00ff00; margin: 10px 0;"></div>
                </div>
                <div id="api_keys" class="tab-content" style="display:none;">
                    <h3>API Keys</h3>
                    <table>
                        <tr>
                            <td>API Key</td>
                            <td>Created At</td>
                            <td>Status</td>
                            <td>Action</td>
                        </tr>
                        {{ api_keys_html|safe }}
                    </table>
                    <h3>Generate New API Key</h3>
                    <button onclick="generateApiKey()">Generate</button>
                    <div id="status_api_keys"></div>
                </div>
                {% if is_super_admin %}
                <div id="admins" class="tab-content" style="display:none;">
                    <h3>Add New Admin</h3>
                    <input type="text" id="new_username" placeholder="Username">
                    <input type="password" id="new_password" placeholder="Password">
                    <button onclick="addAdmin()">Add</button>
                    <div id="status_admins" style="color: #00ff00; margin: 10px 0;"></div>
                </div>
                {% endif %}
            </div>
        </div>
    </body>
    </html>
    ''', keys_html=keys_html, api_keys_html=api_keys_html, is_super_admin=is_super_admin)

@app.route('/admin/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    send_discord_log("Admin logged out")
    return redirect(url_for('login'))

# Vercel serverless function handler
from serverless_wsgi import handle_request

def handler(event, context):
    return handle_request(app, event, context)
