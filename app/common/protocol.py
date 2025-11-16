#!/usr/bin/env python3
"""
SecureChat Protocol Definition using Pydantic.

Message types:
1. HELLO - Client initiates connection with certificate
2. SERVER_HELLO - Server responds with certificate
3. DH_CLIENT - Client sends DH public key
4. DH_SERVER - Server sends DH public key
5. REGISTER - Client registers account (encrypted with temp key)
6. REGISTER_RESPONSE - Server confirms registration
7. LOGIN - Client logs in (encrypted with temp key)
8. LOGIN_RESPONSE - Server confirms login
9. MESSAGE - Chat message (encrypted with session key, signed)
10. RECEIPT - Session closure with transcript hash and signature
11. ERROR - Error message
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from enum import Enum


class MessageType(str, Enum):
    """Message type enumeration."""
    HELLO = "hello"
    SERVER_HELLO = "server_hello"
    DH_CLIENT = "dh_client"
    DH_SERVER = "dh_server"
    REGISTER = "register"
    REGISTER_RESPONSE = "register_response"
    LOGIN = "login"
    LOGIN_RESPONSE = "login_response"
    MESSAGE = "message"
    RECEIPT = "receipt"
    ERROR = "error"


class Hello(BaseModel):
    """
    Client initiates connection.
    
    Sends:
    - Certificate (PEM format, hex encoded)
    """
    type: Literal[MessageType.HELLO] = MessageType.HELLO
    certificate: str = Field(..., description="X.509 certificate in PEM format (hex encoded)")
    
    class Config:
        use_enum_values = True


class ServerHello(BaseModel):
    """
    Server responds with its certificate.
    
    Sends:
    - Certificate (PEM format, hex encoded)
    """
    type: Literal[MessageType.SERVER_HELLO] = MessageType.SERVER_HELLO
    certificate: str = Field(..., description="X.509 certificate in PEM format (hex encoded)")
    
    class Config:
        use_enum_values = True


class DHClient(BaseModel):
    """
    Client sends DH public key for temporary key agreement.
    
    Used for:
    - Registration/Login temporary encryption
    """
    type: Literal[MessageType.DH_CLIENT] = MessageType.DH_CLIENT
    public_key: str = Field(..., description="DH public key (256 bytes hex encoded)")
    
    class Config:
        use_enum_values = True


class DHServer(BaseModel):
    """
    Server sends DH public key for temporary key agreement.
    
    Used for:
    - Registration/Login temporary encryption
    """
    type: Literal[MessageType.DH_SERVER] = MessageType.DH_SERVER
    public_key: str = Field(..., description="DH public key (256 bytes hex encoded)")
    
    class Config:
        use_enum_values = True


class Register(BaseModel):
    """
    Client registers new account.
    
    Encrypted with: Temporary AES key from DH exchange
    Signed by: Client's RSA private key
    
    Contains:
    - Email address
    - Password
    """
    type: Literal[MessageType.REGISTER] = MessageType.REGISTER
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password (plaintext in encrypted message)")
    ciphertext: str = Field(..., description="Encrypted (email + password) with temp AES key (hex)")
    signature: str = Field(..., description="RSA signature of ciphertext (hex)")
    
    class Config:
        use_enum_values = True


class RegisterResponse(BaseModel):
    """
    Server confirms registration.
    
    Encrypted with: Temporary AES key from DH exchange
    Signed by: Server's RSA private key
    """
    type: Literal[MessageType.REGISTER_RESPONSE] = MessageType.REGISTER_RESPONSE
    success: bool = Field(..., description="Registration success status")
    user_id: Optional[int] = Field(None, description="Assigned user ID if successful")
    ciphertext: str = Field(..., description="Encrypted response with temp AES key (hex)")
    signature: str = Field(..., description="RSA signature of ciphertext (hex)")
    
    class Config:
        use_enum_values = True


class Login(BaseModel):
    """
    Client logs in.
    
    Encrypted with: Temporary AES key from DH exchange
    Signed by: Client's RSA private key
    
    Contains:
    - Email address
    - Password
    """
    type: Literal[MessageType.LOGIN] = MessageType.LOGIN
    email: str = Field(..., description="User email")
    password: str = Field(..., description="User password (plaintext in encrypted message)")
    ciphertext: str = Field(..., description="Encrypted (email + password) with temp AES key (hex)")
    signature: str = Field(..., description="RSA signature of ciphertext (hex)")
    
    class Config:
        use_enum_values = True


class LoginResponse(BaseModel):
    """
    Server confirms login and sends session details.
    
    Encrypted with: Temporary AES key from DH exchange
    Signed by: Server's RSA private key
    """
    type: Literal[MessageType.LOGIN_RESPONSE] = MessageType.LOGIN_RESPONSE
    success: bool = Field(..., description="Login success status")
    user_id: Optional[int] = Field(None, description="Authenticated user ID")
    session_id: Optional[int] = Field(None, description="New session ID")
    ciphertext: str = Field(..., description="Encrypted response with temp AES key (hex)")
    signature: str = Field(..., description="RSA signature of ciphertext (hex)")
    
    class Config:
        use_enum_values = True


class Message(BaseModel):
    """
    Chat message during active session.
    
    Encrypted with: Session AES key (from DH exchange after login)
    Signed by: Sender's RSA private key
    
    Signature computed over: sequence_number + timestamp + ciphertext
    """
    type: Literal[MessageType.MESSAGE] = MessageType.MESSAGE
    sender_id: int = Field(..., description="Sender user ID")
    session_id: int = Field(..., description="Session ID")
    sequence_number: int = Field(..., description="Message sequence number in session")
    timestamp: int = Field(..., description="Unix timestamp of message")
    ciphertext: str = Field(..., description="Encrypted message with session AES key (hex)")
    signature: str = Field(..., description="RSA signature of (seq + ts + ct) (hex)")
    
    class Config:
        use_enum_values = True


class Receipt(BaseModel):
    """
    Session closure receipt with non-repudiation proof.
    
    Signed by: Both client and server RSA private keys
    
    Contains:
    - Transcript hash (SHA-256 of entire session)
    - Signature (RSA signature of transcript hash)
    """
    type: Literal[MessageType.RECEIPT] = MessageType.RECEIPT
    sender_id: int = Field(..., description="Sender user ID")
    session_id: int = Field(..., description="Session ID")
    transcript_hash: str = Field(..., description="SHA-256 of entire transcript (hex)")
    signature: str = Field(..., description="RSA signature of transcript hash (hex)")
    
    class Config:
        use_enum_values = True


class Error(BaseModel):
    """
    Error message.
    
    Sent by either party to indicate errors.
    """
    type: Literal[MessageType.ERROR] = MessageType.ERROR
    error_code: str = Field(..., description="Error code (e.g., 'INVALID_CERT', 'AUTH_FAILED')")
    error_message: str = Field(..., description="Human-readable error message")
    
    class Config:
        use_enum_values = True


# Union type for all messages
Message_Union = (
    Hello | ServerHello | DHClient | DHServer |
    Register | RegisterResponse | Login | LoginResponse |
    Message | Receipt | Error
)


def message_to_json(msg: BaseModel) -> str:
    """
    Serialize a message to JSON.
    
    Args:
        msg: Pydantic model instance
        
    Returns:
        str: JSON representation
    """
    return msg.model_dump_json()


def json_to_message(json_str: str) -> BaseModel:
    """
    Deserialize JSON to appropriate message type.
    
    Args:
        json_str: JSON string
        
    Returns:
        Pydantic model instance
        
    Raises:
        ValueError: If JSON is invalid or unknown message type
    """
    import json
    
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
    
    msg_type = data.get('type')
    
    if msg_type == MessageType.HELLO:
        return Hello(**data)
    elif msg_type == MessageType.SERVER_HELLO:
        return ServerHello(**data)
    elif msg_type == MessageType.DH_CLIENT:
        return DHClient(**data)
    elif msg_type == MessageType.DH_SERVER:
        return DHServer(**data)
    elif msg_type == MessageType.REGISTER:
        return Register(**data)
    elif msg_type == MessageType.REGISTER_RESPONSE:
        return RegisterResponse(**data)
    elif msg_type == MessageType.LOGIN:
        return Login(**data)
    elif msg_type == MessageType.LOGIN_RESPONSE:
        return LoginResponse(**data)
    elif msg_type == MessageType.MESSAGE:
        return Message(**data)
    elif msg_type == MessageType.RECEIPT:
        return Receipt(**data)
    elif msg_type == MessageType.ERROR:
        return Error(**data)
    else:
        raise ValueError(f"Unknown message type: {msg_type}")
