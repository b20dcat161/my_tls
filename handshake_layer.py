
from dataclasses import dataclass,field
from enum import Enum

class HandshakeType(Enum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    MESSAGE_HASH = 254
    RESERVED = 255
    

@dataclass
class Handshake:
    msg_type: int
    body: bytes
    length: int = 0
    def __post_init__(self):
        self.length = len(self.body)
    def to_bytes(self):
        return self.msg_type.to_bytes()+self.length.to_bytes(3)+self.body