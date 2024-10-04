from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass,field
from enum import Enum


@dataclass
class Extension:
    extension_type: int = 65535
    extension_length: int = 0
    extension_data: bytes = b''
    
    def __post_init__(self):
        self.extension_length =len(self.extension_data)
    def to_bytes(self):
        return self.extension_type.to_bytes(2,'big')+self.extension_length.to_bytes(2,'big')+self.extension_data

class ExtensionType(Enum):
    SERVER_NAME = 0
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    PRE_SHARED_KEY = 41 # Vị trí bắt buộc xuất hiện cuối cùng ở client hello, ở server thì tùy vị trí
    SUPPORTED_VERSIONS = 43
    PSK_KEY_EXCHANGE_MODES = 45 
    KEY_SHARE = 51
    
# extensiondata của SUPORTED_GROUP
class NamedGroup(Enum):
    secp256r1 = b'\x00\x17'
    X25519 = b'\x00\x1D'
    ffdhe2048 = b'\x01\x00'
    ffdhe_private_use = b'\x01\xFC'
@dataclass
class NamedGroupList():
    named_group_list_length: int = 0
    named_group_list: bytes = b''
    def __post_init__(self):
        self.named_group_list_length = len(self.named_group_list) 
    def to_bytes(self):
        return self.named_group_list_length.to_bytes(2,'big') + self.named_group_list
    
#extension data của signature_algorithms
from enum import Enum

class SignatureScheme(Enum):
    rsa_pkcs1_sha256 = b'\x04\x01'
    rsa_pkcs1_sha384 = b'\x05\x01'
    rsa_pkcs1_sha512 = b'\x06\x01'

    ecdsa_secp256r1_sha256 = b'\x04\x03'
    ecdsa_secp384r1_sha384 = b'\x05\x03'
    ecdsa_secp521r1_sha512 = b'\x06\x03'

    rsa_pss_rsae_sha256 = b'\x08\x04'
    rsa_pss_rsae_sha384 = b'\x08\x05'
    rsa_pss_rsae_sha512 = b'\x08\x06'

    ed25519 = b'\x08\x07'
    ed448 = b'\x08\x08'

    rsa_pss_pss_sha256 = b'\x08\x09'
    rsa_pss_pss_sha384 = b'\x08\x0A'
    rsa_pss_pss_sha512 = b'\x08\x0B'

    rsa_pkcs1_sha1 = b'\x02\x01'
    ecdsa_sha1 = b'\x02\x03'

    private_use_start = b'\xFE\x00'
    private_use_end = b'\xFF\xFF'

    max_value = b'\xFF\xFF'


@dataclass
class SignatureSchemeList:
    supported_signature_algorithms_length: int = 0
    supported_signature_algorithms: bytes = b''
    def __post_init__(self):
        self.supported_signature_algorithms_length = len(self.supported_signature_algorithms)
    def to_bytes(self):
        return self.supported_signature_algorithms_length.to_bytes(2,'big') + self.supported_signature_algorithms
    
# extension_data:
@dataclass
class PskIdentity:
    identity_length: int = 1
    identity: bytes = b'\x02'
    obfuscated_ticket_age : int = 0
    def __post_init__(self):
        self.identity_length = len(self.identity)
    def to_bytes(self):
        return self.identity_length.to_bytes(2,'big') + self.identity +\
            self.obfuscated_ticket_age.to_bytes(4,'big')
@dataclass
class OfferedPsks:
    identities_length: int = 7
    identities: bytes = PskIdentity().to_bytes()
    binders_length: int = 33
    binders: bytes = b'\x03'*33
    def __post_init__(self):
        self.identities_length = len(self.identities)
    def to_bytes(self):
        return self.identities_length.to_bytes(2,'big') + self.identities +\
            self.binders_length.to_bytes(2,'big') + self.binders
@dataclass
class PreSharedKeyEXtension:
    offeredpsks: OfferedPsks
    def to_bytes(self):
        return self.offeredpsks.to_bytes()
    
@dataclass
class SupportedVersions:
    versions_lenthg: int = 2
    versions: bytes = b'\x03\x04'
    def to_bytes(self):
        return self.versions_lenthg.to_bytes(1,'big') + self.versions
    
    
# @dataclass 
# class ServerName:
#     name_type: int = 0

@dataclass 
class KeyShareEntry:
    group: bytes = NamedGroup.X25519.value
    key_exchange_length: int = 32
    key_exchange: bytes = b''
    def to_bytes(self):
        return self.group + self.key_exchange_length.to_bytes(2,'big') + self.key_exchange

@dataclass 
class KeyShareClientHello:
    client_share_length: int = 36
    client_share: KeyShareEntry = None #0-2kb
    
    def to_bytes(self):
        return self.client_share_length.to_bytes(2,'big') +self.client_share.to_bytes()
    
# @dataclass
# class UncompressedPointRepresentation:
#     legacy_form: int = 4
#     X: bytes = b'\x00' * 32
#     Y: bytes = b'\x00' * 32
    
#     def to_bytes(self):
#         return self.legacy_form.to_bytes(1,'big') + self.X + self.Y


@dataclass
class ServerName:
    name_type: int = 0
    server_name_length: int = 0
    server_name: str = '' 
    
    def __post_init__(self):
        self.server_name_length = len(self.server_name)
    def to_bytes(self):
        return self.name_type.to_bytes(1,'big') + self.server_name_length.to_bytes(2,'big') +\
            self.server_name.encode('utf-8')

# @dataclass
# class ServerNameExtension:
#     extension_type: int = 0x0000 
#     server_name_list: list = None  
    
#     def __post_init__(self):
#         if self.server_name_list is None:
#             self.server_name_list = []

#     def to_bytes(self):
#         server_names_bytes = b''.join(server_name.to_bytes() for server_name in self.server_name_list)
#         server_names_length = len(server_names_bytes)
        
#         return self.extension_type.to_bytes(2, 'big') + server_names_length.to_bytes(2, 'big') + server_names_bytes

@dataclass
class ExtensionDataList():
    data_length: int = 1
    data: bytes = b''
    
    def __post_init__(self):
        self.data_length = len(self.data)
        print(self.data_length)
    def to_bytes(self):
        return self.data_length.to_bytes(2,'big') + self.data
