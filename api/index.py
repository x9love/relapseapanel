import os
import json
import logging
import requests
import psycopg2
from flask import Flask, request, jsonify, render_template_string, redirect, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secret_key")

# Логирование
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ===== API для Patch Notes =====

@app.route('/api/update_patch_notes_webhook', methods=['POST'])
def update_patch_notes_webhook():
    if not session.get('logged_in'):
        logger.warning("Unauthorized access attempt to /api/update_patch_notes_webhook")
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    webhook_url = data.get('webhook_url')
    if not webhook_url:
        return jsonify({'error': 'Webhook URL required'}), 400
    
    try:
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
        c = conn.cursor()
        c.execute("""INSERT INTO settings (key, value) VALUES (%s, %s)
                     ON CONFLICT (key) DO UPDATE SET value=%s""",
                  ('patch_notes_webhook_url', webhook_url, webhook_url))
        conn.commit()
        conn.close()
        
        logger.info("Patch notes webhook updated")
        return jsonify({'message': 'Patch notes webhook updated'})
    except Exception as e:
        logger.error(f"Failed to update patch notes webhook: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/send_patch_notes', methods=['POST'])
def send_patch_notes():
    if not session.get('logged_in'):
        logger.warning("Unauthorized access attempt to /api/send_patch_notes")
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    notes = data.get('notes')
    if not notes:
        return jsonify({'error': 'Notes content required'}), 400
    
    try:
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key=%s", ('patch_notes_webhook_url',))
        result = c.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'Patch notes webhook not configured'}), 400
        
        webhook_url = result[0]
        payload = {"content": f"**Patch Notes**\n{notes}"}
        response = requests.post(webhook_url, json=payload)
        response.raise_for_status()
        
        logger.info("Patch notes sent successfully")
        return jsonify({'message': 'Patch notes sent'})
    except Exception as e:
        logger.error(f"Failed to send patch notes: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ===== Админ-панель =====

@app.route('/admin')
def admin_panel():
    if not session.get('logged_in'):
        return redirect('/login')
    
    return render_template_string("""
<!DOCTYPE html>
<html>
<head>
    <title>Admin Panel</title>
    <style>
        body { background-color: #1e1e1e; color: white; font-family: Arial; }
        .tab-content { display: none; padding: 20px; }
        .tabs button { padding: 10px; background: #333; color: white; border: none; margin-right: 5px; cursor: pointer; }
        .tabs button:hover { background: #444; }
        textarea, input { background: #2b2b2b; color: white; border: none; padding: 8px; border-radius: 5px; width: 100%; }
        button { background: #007acc; color: white; padding: 8px 12px; border: none; border-radius: 5px; cursor: pointer; }
        button:hover { background: #005f99; }
    </style>
</head>
<body>
    <h1>Admin Panel</h1>
    <div class="tabs">
        <button onclick="openTab('dashboard')">Dashboard</button>
        <button onclick="openTab('settings')">Settings</button>
        <button onclick="openTab('patch_notes')">Patch Notes</button>
    </div>

    <div id="dashboard" class="tab-content" style="display:block;">
        <h2>Welcome to the Admin Dashboard</h2>
    </div>

    <div id="settings" class="tab-content">
        <h2>Settings</h2>
        <p>Тут твои настройки...</p>
    </div>

    <div id="patch_notes" class="tab-content">
        <h2>Patch Notes</h2>
        <h3>Patch Notes Webhook URL</h3>
        <input type="text" id="patch_notes_webhook" placeholder="Webhook URL">
        <button onclick="updatePatchNotesWebhook()">Save Webhook</button>
        <h3>Send Patch Notes</h3>
        <textarea id="patch_notes_text" placeholder="Write patch notes here..." style="height:150px;"></textarea>
        <button onclick="sendPatchNotes()">Send</button>
        <div id="status_patch_notes" style="color: #00ff00; margin: 10px 0;"></div>
    </div>

    <script>
        function openTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(tab => tab.style.display = 'none');
            document.getElementById(tabId).style.display = 'block';
        }

        async function updatePatchNotesWebhook() {
            const webhookUrl = document.getElementById('patch_notes_webhook').value;
            const response = await fetch('/api/update_patch_notes_webhook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ webhook_url: webhookUrl })
            });
            const result = await response.json();
            const statusDiv = document.getElementById('status_patch_notes');
            statusDiv.innerText = response.ok ? 'Webhook updated successfully' : `Error: ${result.error}`;
        }

        async function sendPatchNotes() {
            const notes = document.getElementById('patch_notes_text').value;
            const response = await fetch('/api/send_patch_notes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ notes })
            });
            const result = await response.json();
            const statusDiv = document.getElementById('status_patch_notes');
            statusDiv.innerText = response.ok ? 'Patch notes sent successfully' : `Error: ${result.error}`;
        }
    </script>
</body>
</html>
""")

# ===== Запуск =====
if __name__ == "__main__":
    app.run(debug=True)
