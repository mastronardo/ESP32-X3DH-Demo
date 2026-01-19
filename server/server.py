import sqlite3
from flask import Flask, request, jsonify, g

app = Flask(__name__)
DATABASE = '/app/data/database.db'

# --- Database Setup ---
def get_db() -> sqlite3.Connection:
    """Get a database connection, creating one if necessary.
    Returns:
        db: sqlite3.Connection
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception) -> None:
    """Close the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_database_on_startup() -> None:
    """Initialize the database if it doesn't exist or is outdated."""
    with app.app_context():
        db = get_db()
        try:
            # Check if our new chat_messages table exists
            db.execute("SELECT id FROM chat_messages LIMIT 1").fetchone()
        except sqlite3.OperationalError:
            print("--- [Server] No database found or schema is old. Initializing... ---")
            db.executescript(
                """
                DROP TABLE IF EXISTS users;
                DROP TABLE IF EXISTS bundles;
                DROP TABLE IF EXISTS opks;
                DROP TABLE IF EXISTS initial_messages;
                DROP TABLE IF EXISTS chat_messages;

                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    ik_b64 TEXT NOT NULL
                );
                
                CREATE TABLE bundles (
                    user_id INTEGER PRIMARY KEY,
                    spk_b64 TEXT NOT NULL,
                    spk_sig_b64 TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );
                
                CREATE TABLE opks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    key_id INTEGER NOT NULL,
                    opk_b64 TEXT NOT NULL,
                    UNIQUE(user_id, key_id),
                    FOREIGN KEY (user_id) REFERENCES users (id)
                );

                CREATE TABLE initial_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_user TEXT UNIQUE NOT NULL,
                    from_user TEXT NOT NULL,
                    ik_b64 TEXT NOT NULL,
                    ek_b64 TEXT NOT NULL,
                    opk_id INTEGER NOT NULL,
                    ciphertext_b64 TEXT NOT NULL,
                    ad_b64 TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL
                );

                CREATE TABLE chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user TEXT NOT NULL,
                    to_user TEXT NOT NULL,
                    ciphertext_b64 TEXT NOT NULL,
                    nonce_b64 TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE INDEX idx_chat_messages_to_from ON chat_messages (to_user, from_user);
                """)
            db.commit()
            print("--- [Server] Database initialized. ---")


# --- X3DH Registration Endpoints ---
@app.route('/get_users', methods=['GET'])
def get_users() -> jsonify:
    """Retrieve a list of all registered usernames."""
    db = get_db()
    try:
        rows = db.execute("SELECT username FROM users").fetchall()
        user_list = [row['username'] for row in rows]
        return jsonify(user_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/register_ik', methods=['POST'])
def register_ik() -> jsonify:
    """Register a user's identity key. Handles duplicate names."""
    data = request.json
    if not data or 'username' not in data or 'ik_b64' not in data:
        return jsonify({"error": "Missing username or ik_b64"}), 400
    
    requested_username = data['username']
    ik_b64 = data['ik_b64']
    
    db = get_db()
    final_username = requested_username
    
    try:
        counter = 1
        while True:
            existing = db.execute("SELECT id FROM users WHERE username = ?", (final_username,)).fetchone()
            if not existing:
                break
            counter += 1
            final_username = f"{requested_username}{counter}"

        db.execute("INSERT INTO users (username, ik_b64) VALUES (?, ?)", (final_username, ik_b64))
        db.commit()
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
    print(f"--- Registered: {final_username} (Requested: {requested_username}) ---")
    
    # Return the actual assigned username so the client can update NVS
    return jsonify({"status": "created", "username": final_username}), 201

@app.route('/register_bundle', methods=['POST'])
def register_bundle() -> jsonify:
    """Register a user's signed prekey bundle and one-time prekeys (OPKs).
    Returns:
        JSON response with status.
    """
    data = request.json
    if not data or 'username' not in data or 'spk_b64' not in data or 'spk_sig_b64' not in data or 'opks_b64' not in data:
        return jsonify({"error": "Missing bundle fields"}), 400

    username = data['username']
    spk_b64 = data['spk_b64']
    spk_sig_b64 = data['spk_sig_b64']
    opks = data['opks_b64'] # This is a list of {"id": int, "key": "b64..."}

    db = get_db()
    
    user = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if not user:
        return jsonify({"error": "User {} not found. Register IK first.".format(username)}), 404
    
    user_id = user['id']

    try:
        with db:
            # 1. Insert/update the signed prekey bundle
            db.execute("""
                INSERT INTO bundles (user_id, spk_b64, spk_sig_b64) 
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    spk_b64 = excluded.spk_b64,
                    spk_sig_b64 = excluded.spk_sig_b64
            """, (user_id, spk_b64, spk_sig_b64))
            
            # 2. Delete old OPKs
            db.execute("DELETE FROM opks WHERE user_id = ?", (user_id,))
            
            # 3. Insert new OPKs
            opk_data = [(user_id, opk['id'], opk['key']) for opk in opks]
            db.executemany("""
                INSERT INTO opks (user_id, key_id, opk_b64)
                VALUES (?, ?, ?)
            """, opk_data)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "bundle created"}), 201

@app.route('/get_bundle/<username>', methods=['GET'])
def get_bundle(username) -> jsonify:
    """Retrieve a user's signed prekey bundle and one-time prekey (OPK).
    Returns:
        JSON response with the bundle and one OPK.
    """
    db = get_db()
    
    # 1. Get user_id and main bundle
    bundle_data = db.execute(
        """
        SELECT u.id, u.ik_b64, b.spk_b64, b.spk_sig_b64
        FROM users u
        LEFT JOIN bundles b ON u.id = b.user_id
        WHERE u.username = ?
        """, (username,)).fetchone()

    if not bundle_data or not bundle_data['spk_b64']:
        return jsonify({"error": "No bundle found for user {}".format(username)}), 404
    
    user_id = bundle_data['id']
    
    # 2. Get one OPK and delete it
    opk_data = None
    opk_id = -1
    
    try:
        with db:
            # Find one OPK
            opk_data_row = db.execute(
                "SELECT id, key_id, opk_b64 FROM opks WHERE user_id = ? LIMIT 1", (user_id,)
            ).fetchone()
            
            if opk_data_row:
                opk_data = dict(opk_data_row)
                opk_id = opk_data['key_id']
                db.execute("DELETE FROM opks WHERE id = ?", (opk_data['id'],))

    except Exception as e:
        print(f"Error fetching OPK: {e}")
        # Continue without an OPK
    
    # 3. Format response
    response = {
        "ik_b64": bundle_data['ik_b64'],
        "spk_b64": bundle_data['spk_b64'],
        "spk_sig_b64": bundle_data['spk_sig_b64'],
    }
    
    if opk_data:
        response["opk_id"] = opk_data['key_id']
        response["opk_b64"] = opk_data['opk_b64']
    else:
        response["opk_id"] = -1 # Signal that no OPK was available

    return jsonify(response)


# --- X3DH Initial Message Endpoints ---
@app.route('/send_initial_message', methods=['POST'])
def send_initial_message() -> jsonify:
    """Send an initial X3DH message to a user to start a new chat.
    Returns:
        JSON response with status.
    """
    data = request.json
    to_user = data.get('to')
    from_user = data.get('from')
    ik_b64 = data.get('ik_b64')
    ek_b64 = data.get('ek_b64')
    opk_id = data.get('opk_id')
    ciphertext_b64 = data.get('ciphertext_b64')
    ad_b64 = data.get('ad_b64')
    nonce_b64 = data.get('nonce_b64')

    if not all([to_user, from_user, ik_b64, ek_b64, ciphertext_b64, ad_b64, nonce_b64]) or opk_id is None:
        return jsonify({"error": "Missing fields for initial message"}), 400
    
    db = get_db()
    if not db.execute("SELECT id FROM users WHERE username = ?", (to_user,)).fetchone():
        return jsonify({"error": "Recipient not found"}), 404
    
    try:
        db.execute(
            """
            INSERT INTO initial_messages (to_user, from_user, ik_b64, ek_b64, opk_id, ciphertext_b64, ad_b64, nonce_b64)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(to_user) DO UPDATE SET
                from_user = excluded.from_user,
                ik_b64 = excluded.ik_b64,
                ek_b64 = excluded.ek_b64,
                opk_id = excluded.opk_id,
                ciphertext_b64 = excluded.ciphertext_b64,
                ad_b64 = excluded.ad_b64,
                nonce_b64 = excluded.nonce_b64
            """, (to_user, from_user, ik_b64, ek_b64, opk_id, ciphertext_b64, ad_b64, nonce_b64))
        db.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "initial message delivered"}), 201

@app.route('/get_initial_message/<username>', methods=['GET'])
def get_initial_message(username) -> jsonify:
    """Retrieve and delete the initial X3DH message for a user.
    Returns:
        JSON response with the initial message fields.
    """
    db = get_db()
    message = db.execute(
        """
        SELECT from_user, ik_b64, ek_b64, opk_id, ciphertext_b64, ad_b64, nonce_b64
        FROM initial_messages 
        WHERE to_user = ?
        """, (username,)).fetchone()

    if not message:
        return jsonify({"error": "No initial message found"}), 404
    
    db.execute("DELETE FROM initial_messages WHERE to_user = ?", (username,))
    db.commit()
    return jsonify(dict(message))


# --- Post-X3DH Chat Message Endpoints ---
@app.route('/send_chat_message', methods=['POST'])
def send_chat_message() -> jsonify:
    """Send a chat message from one user to another.
    Returns:
        JSON response with status.
    """
    data = request.json
    from_user = data.get('from')
    to_user = data.get('to')
    ciphertext_b64 = data.get('ciphertext_b64')
    nonce_b64 = data.get('nonce_b64')

    if not all([from_user, to_user, ciphertext_b64, nonce_b64]):
        return jsonify({"error": "Missing chat message fields"}), 400

    db = get_db()
    
    try:
        db.execute(
            """
            INSERT INTO chat_messages (from_user, to_user, ciphertext_b64, nonce_b64)
            VALUES (?, ?, ?, ?)
            """, (from_user, to_user, ciphertext_b64, nonce_b64))
        db.commit()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "chat message delivered"}), 201


@app.route('/get_chat_messages/<to_user>/from/<from_user>', methods=['GET'])
def get_chat_messages(to_user, from_user) -> jsonify:
    """Retrieve and delete all chat messages sent from one user to another.
    Returns:
        JSON response with a list of messages.
    """
    db = get_db()
    messages = []
    
    try:
        with db:
            # 1. Select all messages for the user from the sender
            rows = db.execute(
                """
                SELECT id, ciphertext_b64, nonce_b64, timestamp
                FROM chat_messages
                WHERE to_user = ? AND from_user = ?
                ORDER BY timestamp ASC
                """, (to_user, from_user)).fetchall()
            
            if not rows:
                return jsonify([]), 200
            
            messages = [dict(row) for row in rows]
            
            # 2. Delete the messages that were just fetched
            ids_to_delete = [row['id'] for row in rows]
            db.executemany("DELETE FROM chat_messages WHERE id = ?", [(id,) for id in ids_to_delete])
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Return only ciphertext and nonce
    response_messages = [{"ciphertext_b64": m["ciphertext_b64"], "nonce_b64": m["nonce_b64"]} for m in messages]
    return jsonify(response_messages), 200


if __name__ == '__main__':
    init_database_on_startup()
    app.run(host='0.0.0.0', port=5001, debug=False)