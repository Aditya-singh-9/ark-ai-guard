"""
Database initialization script for cloud deployment.
Run once after deploying to create all tables.
"""
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from app.database.db import engine
from app.models import Base

def init():
    print("Creating all database tables...")
    Base.metadata.create_all(bind=engine)
    print("✅ Database initialized successfully!")

if __name__ == "__main__":
    init()
