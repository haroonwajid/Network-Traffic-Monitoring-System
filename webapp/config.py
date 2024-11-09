import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
    DATABASE_PATH = os.environ.get('DATABASE_PATH') or 'network_metrics.db' 