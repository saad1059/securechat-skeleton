-- SecureChat Database Initialization Script
-- Run this script to create all required tables

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(256) NOT NULL,  -- SHA-256 hash (hex string)
    salt VARCHAR(32) NOT NULL,             -- Random salt for password hashing
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create sessions table (tracks active and closed sessions)
CREATE TABLE IF NOT EXISTS sessions (
    session_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    session_receipt VARCHAR(512),          -- SHA-256 of entire transcript, signed with RSA
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create messages table (stores encrypted chat messages)
CREATE TABLE IF NOT EXISTS messages (
    message_id INT AUTO_INCREMENT PRIMARY KEY,
    session_id INT NOT NULL,
    sender_id INT NOT NULL,
    sequence_number INT NOT NULL,
    timestamp BIGINT NOT NULL,             -- Unix timestamp
    ciphertext LONGBLOB NOT NULL,          -- AES-128 encrypted message
    signature VARCHAR(512) NOT NULL,        -- RSA digital signature (hex string)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_messages_session_id ON messages(session_id);
CREATE INDEX IF NOT EXISTS idx_messages_sender_id ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_messages_sequence ON messages(session_id, sequence_number);

-- Verify tables created
SELECT 'Database initialization complete!' AS status;
