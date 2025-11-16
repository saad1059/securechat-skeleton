#!/usr/bin/env python3
"""
Initialize the SecureChat SQLite database.
Creates all required tables for the secure chat system.
"""

import sqlite3
from pathlib import Path

# Database file path
DB_PATH = Path(__file__).parent.parent / 'securechat.db'

def init_database():
    """Initialize SQLite database with required tables"""
    try:
        # Create database connection
        connection = sqlite3.connect(str(DB_PATH))
        cursor = connection.cursor()
        
        print(f"Initializing SQLite database at: {DB_PATH}")
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("✅ Created 'users' table")
        
        # Create sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                closed_at TIMESTAMP,
                session_receipt TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        ''')
        print("✅ Created 'sessions' table")
        
        # Create messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL,
                sender_id INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                signature TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        ''')
        print("✅ Created 'messages' table")
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_session_id ON messages(session_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sequence ON messages(session_id, sequence_number)')
        print("✅ Created indexes")
        
        connection.commit()
        connection.close()
        
        print(f"\n✅ Database initialized successfully!")
        print(f"📁 Database file: {DB_PATH}")
        print(f"📊 Size: {DB_PATH.stat().st_size} bytes")
        
    except sqlite3.Error as err:
        print(f"❌ Database error: {err}")
        exit(1)
    except Exception as err:
        print(f"❌ Error: {err}")
        exit(1)

if __name__ == '__main__':
    init_database()
