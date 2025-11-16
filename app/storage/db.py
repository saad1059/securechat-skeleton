#!/usr/bin/env python3
"""
Database layer for SecureChat user management.

Provides functions to:
- Register new users with salted password hashing
- Authenticate users by email/password
- Store and retrieve user credentials
- Hash passwords with SHA-256 + salt
"""

import sqlite3
import hashlib
import os
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class User:
    """User data class."""
    user_id: int
    email: str
    password_hash: str
    salt: str


class Database:
    """SQLite database operations for user management."""
    
    def __init__(self, db_path: str = 'securechat.db'):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
    
    def _get_connection(self):
        """Get a database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def _hash_password(self, password: str, salt: str = None) -> Tuple[str, str]:
        """
        Hash a password with SHA-256 and a random salt.
        
        Args:
            password: Plain text password
            salt: Optional salt (if None, generates random)
            
        Returns:
            tuple: (password_hash, salt) both as hex strings
        """
        # Generate salt if not provided
        if salt is None:
            salt = os.urandom(16).hex()
        
        # Combine password and salt, then hash with SHA-256
        password_bytes = password.encode('utf-8')
        salt_bytes = bytes.fromhex(salt)
        
        # Create hash: SHA256(password + salt)
        hash_obj = hashlib.sha256(password_bytes + salt_bytes)
        password_hash = hash_obj.hexdigest()
        
        return password_hash, salt
    
    def _verify_password(self, password: str, stored_hash: str, salt: str) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: Plain text password to verify
            stored_hash: Stored password hash (hex string)
            salt: Stored salt (hex string)
            
        Returns:
            bool: True if password matches, False otherwise
        """
        computed_hash, _ = self._hash_password(password, salt)
        return computed_hash == stored_hash
    
    def register_user(self, email: str, password: str) -> Tuple[bool, str]:
        """
        Register a new user.
        
        Args:
            email: User email (must be unique)
            password: Plain text password
            
        Returns:
            tuple: (success, message)
        """
        if not email or not password:
            return False, "Email and password required"
        
        # Hash password with salt
        password_hash, salt = self._hash_password(password)
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Insert user
            cursor.execute(
                '''INSERT INTO users (email, password_hash, salt)
                   VALUES (?, ?, ?)''',
                (email, password_hash, salt)
            )
            
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            return True, f"User registered successfully (ID: {user_id})"
        
        except sqlite3.IntegrityError:
            return False, f"Email already registered: {email}"
        except Exception as e:
            return False, f"Registration failed: {e}"
    
    def authenticate_user(self, email: str, password: str) -> Tuple[bool, Optional[User], str]:
        """
        Authenticate a user by email and password.
        
        Args:
            email: User email
            password: Plain text password
            
        Returns:
            tuple: (success, User object or None, message)
        """
        if not email or not password:
            return False, None, "Email and password required"
        
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Query user by email
            cursor.execute(
                'SELECT user_id, email, password_hash, salt FROM users WHERE email = ?',
                (email,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return False, None, f"User not found: {email}"
            
            # Verify password
            user_id, stored_email, stored_hash, stored_salt = row
            
            if self._verify_password(password, stored_hash, stored_salt):
                user = User(
                    user_id=user_id,
                    email=stored_email,
                    password_hash=stored_hash,
                    salt=stored_salt
                )
                return True, user, "Authentication successful"
            else:
                return False, None, "Invalid password"
        
        except Exception as e:
            return False, None, f"Authentication failed: {e}"
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            User object or None
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT user_id, email, password_hash, salt FROM users WHERE user_id = ?',
                (user_id,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return User(
                user_id=row[0],
                email=row[1],
                password_hash=row[2],
                salt=row[3]
            )
        except Exception:
            return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email.
        
        Args:
            email: User email
            
        Returns:
            User object or None
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT user_id, email, password_hash, salt FROM users WHERE email = ?',
                (email,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return User(
                user_id=row[0],
                email=row[1],
                password_hash=row[2],
                salt=row[3]
            )
        except Exception:
            return None
    
    def user_exists(self, email: str) -> bool:
        """
        Check if user exists by email.
        
        Args:
            email: User email
            
        Returns:
            bool: True if user exists
        """
        return self.get_user_by_email(email) is not None
    
    def list_users(self) -> list:
        """
        Get list of all users (email only, no passwords).
        
        Returns:
            list: List of (user_id, email) tuples
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('SELECT user_id, email FROM users ORDER BY user_id')
            users = cursor.fetchall()
            conn.close()
            
            return [(row[0], row[1]) for row in users]
        except Exception:
            return []
    
    def delete_user(self, user_id: int) -> Tuple[bool, str]:
        """
        Delete a user by ID.
        
        Args:
            user_id: User ID
            
        Returns:
            tuple: (success, message)
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
            conn.commit()
            
            if cursor.rowcount == 0:
                conn.close()
                return False, f"User not found: {user_id}"
            
            conn.close()
            return True, f"User deleted: {user_id}"
        except Exception as e:
            return False, f"Deletion failed: {e}"
