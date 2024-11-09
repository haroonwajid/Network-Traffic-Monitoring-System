from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import os
import sqlite3
import time

app = Flask(__name__, 
    template_folder=os.path.abspath('templates'),
    static_folder=os.path.abspath('static'))
socketio = SocketIO(app, cors_allowed_origins="*")

def get_latest_stats():
    try:
        # Construct the absolute path to the database
        db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../network_metrics.db'))
        
        if not os.path.exists(db_path):
            print(f"Database file not found at: {db_path}")
            return None

        # Connect to the SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Fetch the latest global stats
        cursor.execute("""
            SELECT total_packets, packets_per_second, timestamp
            FROM global_stats
            ORDER BY timestamp DESC
            LIMIT 1
        """)
        stats = cursor.fetchone()

        # Fetch protocol distribution for the last 60 seconds
        cursor.execute("""
            SELECT protocol, SUM(count) as total
            FROM protocol_stats
            WHERE timestamp >= strftime('%s', 'now') - 60
            GROUP BY protocol
            ORDER BY total DESC
        """)
        protocols = cursor.fetchall()

        # Fetch recent connections for the last 60 seconds
        cursor.execute("""
            SELECT source_ip, source_port, dest_ip, dest_port, protocol, packets
            FROM connection_stats
            WHERE timestamp >= strftime('%s', 'now') - 60
            ORDER BY timestamp DESC
            LIMIT 10
        """)
        connections = cursor.fetchall()

        conn.close()

        return {
            'total_packets': stats[0] if stats else 0,
            'packets_per_second': float(stats[1]) if stats else 0.0,
            'protocols': {proto: count for proto, count in protocols},
            'connections': [{
                'source_ip': conn[0],
                'source_port': conn[1],
                'dest_ip': conn[2],
                'dest_port': conn[3],
                'protocol': conn[4],
                'packets': conn[5]
            } for conn in connections],
            'timestamp': stats[2] if stats else int(time.time())
        }
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/stats')
def get_stats():
    stats = get_latest_stats()
    return jsonify(stats if stats else {'error': 'No data available'})

def emit_stats():
    while True:
        stats = get_latest_stats()
        if stats:
            socketio.emit('stats_update', stats)
        socketio.sleep(1)  # Update every second

if __name__ == '__main__':
    try:
        print("Starting server...")
        from threading import Thread
        Thread(target=emit_stats, daemon=True).start()
        socketio.run(app, host='0.0.0.0', port=5001, debug=True)
    except Exception as e:
        print(f"Error starting server: {e}")