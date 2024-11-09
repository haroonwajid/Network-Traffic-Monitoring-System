import sqlite3
from datetime import datetime, timedelta

class DatabaseManager:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def get_global_stats(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT total_packets, packets_per_second, timestamp
                FROM global_stats
                ORDER BY timestamp DESC
                LIMIT 1
            """)
            return cursor.fetchone()

    def get_protocol_stats(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT protocol, count
                FROM protocol_stats
                WHERE timestamp = (
                    SELECT MAX(timestamp) FROM protocol_stats
                )
            """)
            return cursor.fetchall()

    def get_connection_stats(self, time_window=300):  # Default 5 minutes
        with self.get_connection() as conn:
            cursor = conn.cursor()
            timestamp_threshold = datetime.now() - timedelta(seconds=time_window)
            cursor.execute("""
                SELECT source_ip, dest_ip, protocol, packets, bytes
                FROM connection_stats
                WHERE timestamp > ?
                ORDER BY packets DESC
                LIMIT 100
            """, (timestamp_threshold.timestamp(),))
            return cursor.fetchall()

def initialize_database():
    db_path = 'network_metrics.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create tables if they don't exist
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS global_stats (
            timestamp INTEGER,
            total_packets INTEGER,
            packets_per_second REAL
        );
        CREATE TABLE IF NOT EXISTS protocol_stats (
            timestamp INTEGER,
            protocol TEXT,
            count INTEGER
        );
        CREATE TABLE IF NOT EXISTS connection_stats (
            timestamp INTEGER,
            source_ip TEXT,
            dest_ip TEXT,
            source_port INTEGER,
            dest_port INTEGER,
            protocol TEXT,
            packets INTEGER
        );
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_database()