from dataclasses import dataclass,field
from enum import Enum
class ContentType(Enum):
    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    HEARDBEAT = 24
    RESEVED = 255
    
@dataclass
class TLSPlaintext:
    type: int
    legacy_record_version: bytes
    fragment: bytes
    length: int = 0
    def __post_init__(self):
        self.length = len(self.fragment)
    def to_bytes(self):
        return self.type.to_bytes(1,'big') + self.legacy_record_version + \
            self.length.to_bytes(2, 'big') + self.fragment