#!/usr/bin/env python3
"""
Session transcript management for non-repudiation.

Provides functions to:
- Store encrypted chat messages in transcript
- Generate session receipt (hash of entire transcript)
- Sign session receipt with RSA private key
- Verify transcript integrity
"""

import hashlib
import sqlite3
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Optional


@dataclass
class Message:
    """Chat message data class."""
    message_id: int
    session_id: int
    sender_id: int
    sequence_number: int
    timestamp: int
    ciphertext: str
    signature: str


class Transcript:
    """Session transcript management."""
    
    def __init__(self, db_path: str = 'securechat.db'):
        """
        Initialize transcript manager.
        
        Args:
            db_path: Path to SQLite database
        """
        self.db_path = Path(db_path)
        
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
    
    def _get_connection(self):
        """Get a database connection."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_session(self, user_id: int) -> Tuple[bool, int, str]:
        """
        Create a new chat session.
        
        Args:
            user_id: ID of user starting session
            
        Returns:
            tuple: (success, session_id, message)
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Insert session
            cursor.execute(
                'INSERT INTO sessions (user_id) VALUES (?)',
                (user_id,)
            )
            
            conn.commit()
            session_id = cursor.lastrowid
            conn.close()
            
            return True, session_id, f"Session created (ID: {session_id})"
        except Exception as e:
            return False, -1, f"Session creation failed: {e}"
    
    def add_message(self, session_id: int, sender_id: int, sequence_number: int,
                    timestamp: int, ciphertext: str, signature: str) -> Tuple[bool, int, str]:
        """
        Add an encrypted message to transcript.
        
        Args:
            session_id: Session ID
            sender_id: Sender user ID
            sequence_number: Sequence number of message in session
            timestamp: Unix timestamp
            ciphertext: Encrypted message (hex string)
            signature: RSA signature of (seq_num + timestamp + ciphertext) (hex string)
            
        Returns:
            tuple: (success, message_id, message)
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Insert message
            cursor.execute(
                '''INSERT INTO messages 
                   (session_id, sender_id, sequence_number, timestamp, ciphertext, signature)
                   VALUES (?, ?, ?, ?, ?, ?)''',
                (session_id, sender_id, sequence_number, timestamp, ciphertext, signature)
            )
            
            conn.commit()
            message_id = cursor.lastrowid
            conn.close()
            
            return True, message_id, f"Message stored (ID: {message_id})"
        except Exception as e:
            return False, -1, f"Failed to store message: {e}"
    
    def get_session_messages(self, session_id: int) -> List[Message]:
        """
        Get all messages in a session.
        
        Args:
            session_id: Session ID
            
        Returns:
            list: List of Message objects, ordered by sequence number
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                '''SELECT message_id, session_id, sender_id, sequence_number, 
                          timestamp, ciphertext, signature
                   FROM messages
                   WHERE session_id = ?
                   ORDER BY sequence_number''',
                (session_id,)
            )
            
            rows = cursor.fetchall()
            conn.close()
            
            messages = [
                Message(
                    message_id=row[0],
                    session_id=row[1],
                    sender_id=row[2],
                    sequence_number=row[3],
                    timestamp=row[4],
                    ciphertext=row[5],
                    signature=row[6]
                )
                for row in rows
            ]
            
            return messages
        except Exception:
            return []
    
    def compute_transcript_hash(self, session_id: int) -> Tuple[bool, Optional[str], str]:
        """
        Compute SHA-256 hash of entire transcript.
        
        Hash is computed over all messages concatenated in sequence order:
        SHA256(msg1_seq + msg1_ts + msg1_ct + msg2_seq + msg2_ts + msg2_ct + ...)
        
        Args:
            session_id: Session ID
            
        Returns:
            tuple: (success, transcript_hash, message)
        """
        try:
            messages = self.get_session_messages(session_id)
            
            if not messages:
                return False, None, "No messages in session"
            
            # Build transcript data
            transcript_data = b''
            
            for msg in messages:
                # Concatenate: sequence_number + timestamp + ciphertext
                transcript_data += str(msg.sequence_number).encode('utf-8')
                transcript_data += str(msg.timestamp).encode('utf-8')
                transcript_data += msg.ciphertext.encode('utf-8')
            
            # Compute SHA-256 hash
            transcript_hash = hashlib.sha256(transcript_data).hexdigest()
            
            return True, transcript_hash, f"Transcript hash computed"
        except Exception as e:
            return False, None, f"Failed to compute transcript hash: {e}"
    
    def close_session(self, session_id: int, session_receipt: str) -> Tuple[bool, str]:
        """
        Close a session and store its receipt (signed transcript hash).
        
        Args:
            session_id: Session ID
            session_receipt: Signed transcript hash (RSA signature as hex string)
            
        Returns:
            tuple: (success, message)
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            # Update session with receipt and close time
            cursor.execute(
                '''UPDATE sessions 
                   SET session_receipt = ?, closed_at = CURRENT_TIMESTAMP
                   WHERE session_id = ?''',
                (session_receipt, session_id)
            )
            
            conn.commit()
            
            if cursor.rowcount == 0:
                conn.close()
                return False, f"Session not found: {session_id}"
            
            conn.close()
            return True, f"Session closed with receipt: {session_receipt[:32]}..."
        except Exception as e:
            return False, f"Failed to close session: {e}"
    
    def get_session_receipt(self, session_id: int) -> Optional[str]:
        """
        Get the session receipt (signed transcript hash).
        
        Args:
            session_id: Session ID
            
        Returns:
            str: Session receipt (hex string) or None if not closed
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                'SELECT session_receipt FROM sessions WHERE session_id = ?',
                (session_id,)
            )
            
            row = cursor.fetchone()
            conn.close()
            
            if not row or not row[0]:
                return None
            
            return row[0]
        except Exception:
            return None
    
    def verify_transcript_integrity(self, session_id: int, transcript_hash: str,
                                   session_receipt: str, public_key) -> Tuple[bool, str]:
        """
        Verify the integrity of a transcript.
        
        Args:
            session_id: Session ID
            transcript_hash: Expected transcript hash (hex string)
            session_receipt: Signed transcript hash (hex string)
            public_key: RSA public key for verification
            
        Returns:
            tuple: (is_valid, message)
        """
        # Recompute transcript hash
        success, computed_hash, msg = self.compute_transcript_hash(session_id)
        
        if not success:
            return False, f"Failed to compute hash: {msg}"
        
        if computed_hash != transcript_hash:
            return False, "Transcript hash mismatch (transcript modified)"
        
        # Verify signature on transcript hash
        from app.crypto.sign import RSASignature
        
        is_valid = RSASignature.verify(
            transcript_hash.encode('utf-8'),
            session_receipt,
            public_key
        )
        
        if is_valid:
            return True, "Transcript integrity verified"
        else:
            return False, "Signature verification failed (possible tampering)"
