from flask import render_template, jsonify
from app import app, socketio
from app.database import DatabaseManager
import time

db = DatabaseManager(app.config['DATABASE_PATH'])

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@socketio.on('connect')
def handle_connect():
    emit_metrics()

def emit_metrics():
    global_stats = db.get_global_stats()
    protocol_stats = db.get_protocol_stats()
    connection_stats = db.get_connection_stats()
    
    socketio.emit('metrics_update', {
        'global_stats': global_stats,
        'protocol_stats': protocol_stats,
        'connection_stats': connection_stats
    })

@socketio.on('request_metrics')
def handle_metrics_request():
    emit_metrics() 