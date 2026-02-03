from os import path, getenv
import sys
import json
import logging
from time import sleep
import ssl
import paho.mqtt.client as mqtt
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.enums import CallbackAPIVersion
import psycopg
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row

# --- Configuration ---
BROKER_HOST = getenv("BROKER_HOST", "rabbitmq")
BROKER_PORT = int(getenv("BROKER_PORT", 8883))
CERTS_PATH = '/app/certs'

# Database Config from Environment Variables
DB_HOST = getenv("DB_HOST", "<YOUR_DB_HOST>")
DB_USER = getenv("DB_USER", "<YOUR_DB_USER>")
DB_PASS = getenv("DB_PASS", "<YOUR_DB_PASSWORD>")
DB_NAME = getenv("DB_NAME", "<YOUR_DB_NAME>")

# Connection String
DSN = f"host={DB_HOST} user={DB_USER} password={DB_PASS} dbname={DB_NAME} port=5432"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Database Management ---
pool = None

def init_db():
    logging.info("--- [Server] Initializing PostgreSQL Database ---")
    retries = 5
    while retries > 0:
        try:
            # We use a pool for thread safety and performance
            global pool
            pool = ConnectionPool(conninfo=DSN, min_size=1, max_size=10, kwargs={"row_factory": dict_row})
            pool.wait(timeout=5)
            
            with pool.connection() as conn:
                conn.execute("SELECT 1") # Test connection
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                        username TEXT UNIQUE NOT NULL,
                        ik_b64 TEXT NOT NULL
                    );
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS bundles (
                        user_id INTEGER PRIMARY KEY,
                        spk_b64 TEXT NOT NULL,
                        spk_sig_b64 TEXT NOT NULL,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS opks (
                        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                        user_id INTEGER NOT NULL,
                        key_id INTEGER NOT NULL,
                        opk_b64 TEXT NOT NULL,
                        UNIQUE(user_id, key_id),
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS initial_messages (
                        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                        to_user TEXT UNIQUE NOT NULL,
                        from_user TEXT NOT NULL,
                        ik_b64 TEXT NOT NULL,
                        ek_b64 TEXT NOT NULL,
                        opk_id INTEGER NOT NULL,
                        ciphertext_b64 TEXT NOT NULL,
                        ad_b64 TEXT NOT NULL,
                        nonce_b64 TEXT NOT NULL
                    );
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS chat_messages (
                        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
                        from_user TEXT NOT NULL,
                        to_user TEXT NOT NULL,
                        ciphertext_b64 TEXT NOT NULL,
                        nonce_b64 TEXT NOT NULL,
                        timestamp TIMESTAMPTZ DEFAULT NOW()
                    );
                """)
                
                conn.execute("CREATE INDEX IF NOT EXISTS idx_chat_msg ON chat_messages (to_user, from_user);")
            
            logging.info("--- [Server] Database Ready ---")
            break
        except Exception as e:
            logging.error(f"FATAL: Could not connect to PostgreSQL: {e}")
            retries -= 1
            sleep(5)
            if retries == 0:
                sys.exit(1)

# --- MQTT Event Handlers ---
def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logging.info("--- [Server] Connected to MQTT Broker ---")
        topics = [
            ("x3dh/register/ik", 1),
            ("x3dh/register/bundle", 1),
            ("x3dh/req/users", 1),
            ("x3dh/req/bundle/+", 1),
            ("x3dh/msg/init", 1),
            ("x3dh/req/inbox/+", 1),
            ("x3dh/msg/chat", 1),
            ("x3dh/req/chat", 1)
        ]
        client.subscribe(topics)
    else:
        logging.error(f"--- [Server] Connection failed with code {reason_code} ---")

def on_message(client, userdata, msg):
    topic = msg.topic
    
    try:
        payload = json.loads(msg.payload.decode())
    except json.JSONDecodeError:
        return

    response_topic = None
    correlation_data = None
    if hasattr(msg, 'properties'):
        if hasattr(msg.properties, 'ResponseTopic'):
            response_topic = msg.properties.ResponseTopic
        if hasattr(msg.properties, 'CorrelationData'):
            correlation_data = msg.properties.CorrelationData

    response = {}
    
    try:
        # Get a fresh connection from the pool
        with pool.connection() as conn:            
            if topic == "x3dh/req/users":
                rows = conn.execute("SELECT username FROM users").fetchall()
                response = {"users": [row['username'] for row in rows]}

            elif topic == "x3dh/register/ik":
                req_user = payload.get("username")
                ik_b64 = payload.get("ik_b64")
                if req_user and ik_b64:
                    final_user = req_user
                    counter = 1
                    while True:
                        exists = conn.execute("SELECT 1 FROM users WHERE username = %s", (final_user,)).fetchone()
                        if not exists: break
                        counter += 1
                        final_user = f"{req_user}{counter}"
                    conn.execute("INSERT INTO users (username, ik_b64) VALUES (%s, %s)", (final_user, ik_b64))
                    response = {"status": "created", "username": final_user}
                else:
                    response = {"error": "Missing fields"}

            elif topic == "x3dh/register/bundle":
                username = payload.get("username")
                opks = payload.get("opks_b64", []) 
                user_row = conn.execute("SELECT id FROM users WHERE username = %s", (username,)).fetchone()
                if user_row:
                    user_id = user_row['id']
                    conn.execute("""
                        INSERT INTO bundles (user_id, spk_b64, spk_sig_b64) 
                        VALUES (%s, %s, %s)
                        ON CONFLICT(user_id) DO UPDATE SET
                            spk_b64 = excluded.spk_b64,
                            spk_sig_b64 = excluded.spk_sig_b64
                    """, (user_id, payload.get("spk_b64"), payload.get("spk_sig_b64")))
                    
                    conn.execute("DELETE FROM opks WHERE user_id = %s", (user_id,))
                    opk_data = [(user_id, opk['id'], opk['key']) for opk in opks]
                    conn.cursor().executemany("INSERT INTO opks (user_id, key_id, opk_b64) VALUES (%s, %s, %s)", opk_data)
                    response = {"status": "bundle created"}
                else:
                    response = {"error": "User not found"}

            elif topic.startswith("x3dh/req/bundle/"):
                target_user = topic.split("/")[-1]
                row = conn.execute("""
                    SELECT u.id, u.ik_b64, b.spk_b64, b.spk_sig_b64
                    FROM users u LEFT JOIN bundles b ON u.id = b.user_id
                    WHERE u.username = %s
                """, (target_user,)).fetchone()
                
                if row and row['spk_b64']:
                    res_data = {"ik_b64": row['ik_b64'], "spk_b64": row['spk_b64'], "spk_sig_b64": row['spk_sig_b64'], "opk_id": -1}
                    opk_row = conn.execute("SELECT id, key_id, opk_b64 FROM opks WHERE user_id = %s LIMIT 1", (row['id'],)).fetchone()
                    if opk_row:
                        res_data["opk_id"] = opk_row["key_id"]
                        res_data["opk_b64"] = opk_row["opk_b64"]
                        conn.execute("DELETE FROM opks WHERE id = %s", (opk_row['id'],))
                    response = res_data
                else:
                    response = {"error": "Bundle not found"}

            elif topic == "x3dh/msg/init":
                to_user = payload.get('to')
                if to_user:
                    conn.execute("""
                        INSERT INTO initial_messages (to_user, from_user, ik_b64, ek_b64, opk_id, ciphertext_b64, ad_b64, nonce_b64)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT(to_user) DO UPDATE SET
                            from_user=excluded.from_user, ik_b64=excluded.ik_b64, ek_b64=excluded.ek_b64,
                            opk_id=excluded.opk_id, ciphertext_b64=excluded.ciphertext_b64, 
                            ad_b64=excluded.ad_b64, nonce_b64=excluded.nonce_b64
                    """, (to_user, payload.get('from'), payload.get('ik_b64'), payload.get('ek_b64'),
                        payload.get('opk_id'), payload.get('ciphertext_b64'), payload.get('ad_b64'), payload.get('nonce_b64')))
                    response = {"status": "delivered"}
                else:
                    response = {"error": "Missing 'to' field"}

            elif topic.startswith("x3dh/req/inbox/"):
                username = topic.split("/")[-1]
                row = conn.execute("SELECT from_user, ik_b64, ek_b64, opk_id, ciphertext_b64, ad_b64, nonce_b64 FROM initial_messages WHERE to_user = %s", (username,)).fetchone()
                if row:
                    response = row # Already a dict due to row_factory
                    conn.execute("DELETE FROM initial_messages WHERE to_user = %s", (username,))
                else:
                    response = {"error": "Empty inbox", "code": 404}

            elif topic == "x3dh/msg/chat":
                conn.execute("INSERT INTO chat_messages (from_user, to_user, ciphertext_b64, nonce_b64) VALUES (%s, %s, %s, %s)", 
                             (payload.get('from'), payload.get('to'), payload.get('ciphertext_b64'), payload.get('nonce_b64')))
                response = {"status": "delivered"}

            elif topic == "x3dh/req/chat":
                rows = conn.execute("SELECT id, ciphertext_b64, nonce_b64 FROM chat_messages WHERE to_user = %s AND from_user = %s ORDER BY timestamp ASC", 
                                    (payload.get("to"), payload.get("from"))).fetchall()
                response = [{"ciphertext_b64": r["ciphertext_b64"], "nonce_b64": r["nonce_b64"]} for r in rows]
                if rows:
                    ids = [r['id'] for r in rows]
                    conn.execute("DELETE FROM chat_messages WHERE id = ANY(%s)", (ids,))

    except Exception as e:
        logging.error(f"Error processing {topic}: {e}")
        response = {"error": str(e)}

    if response_topic:
        reply_props = Properties(PacketTypes.PUBLISH)
        if correlation_data: reply_props.CorrelationData = correlation_data
        client.publish(response_topic, json.dumps(response), properties=reply_props)

if __name__ == '__main__':
    init_db()
    
    # --- MQTT Client Setup ---
    client = mqtt.Client(client_id="x3dh-backend-service", protocol=mqtt.MQTTv5, callback_api_version=CallbackAPIVersion.VERSION2)
    client.on_connect = on_connect
    client.on_message = on_message

    ca_cert = path.join(CERTS_PATH, "ca.crt")
    server_cert = path.join(CERTS_PATH, "tls.crt")
    server_key = path.join(CERTS_PATH, "tls.key")

    # Configure TLS if certs are available
    if path.exists(ca_cert) and path.exists(server_cert):
        print(f"--- [Server] Loading certs from {CERTS_PATH} ---")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=ca_cert)
        context.load_cert_chain(certfile=server_cert, keyfile=server_key)
        context.check_hostname = False 
        context.verify_mode = ssl.CERT_NONE
        client.tls_set_context(context)

    print(f"--- [Server] Connecting to {BROKER_HOST}:{BROKER_PORT} ---", flush=True)
    client.connect(BROKER_HOST, BROKER_PORT, 60)
    client.loop_forever()