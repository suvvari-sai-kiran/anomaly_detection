from flask import Flask, jsonify
import mysql.connector
from mysql_config import get_db_config

app = Flask(__name__)

@app.route("/live")
def live_data():
    conn = mysql.connector.connect(**get_db_config())
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM traffic2025_logs ORDER BY timestamp DESC LIMIT 50")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(rows)

@app.route("/anomalies")
def anomalies_data():
    conn = mysql.connector.connect(**get_db_config())
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM anomaly2025_ips ORDER BY detected_at DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(rows)

if __name__ == "__main__":
    app.run(debug=True)
