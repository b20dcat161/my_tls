
from dataclasses import dataclass,field
from enum import Enum
from extension import  *
from record_layer import *
from handshake_layer import *
@dataclass
class ClientHello:
    import time, os
    legacy_version : bytes = b'\x03\x03'
    random : bytes = int(time.time()).to_bytes(4,'big')+os.urandom(28)
    legacy_session_id_length: int = 0
    legacy_session_id: bytes = b''
    cipher_suite_length: int = 2
    cipher_suite: bytes = b'\x13\x02'
    legacy_compression_method_length: int = 1
    legacy_compression_method: bytes = b'\x00'
    extension_length: int = 0
    extension: bytes = b''
    def __post_init__(self):
        self.extension_length = len(self.extension)
    def to_bytes(self):
        return self.legacy_version + self.random +\
            self.legacy_session_id_length.to_bytes(1,'big') + self.legacy_session_id +\
            self.cipher_suite_length.to_bytes(2,'big') + self.cipher_suite +\
            self.legacy_compression_method_length.to_bytes(1,'big') + self.legacy_compression_method + \
            self.extension_length.to_bytes(2,'big') +self.extension

def gen_client_hello_extension(share_key):
        # server_name data:
        extensions = b''
        server_name = ExtensionDataList(data=ServerName(server_name='ghtk.me').to_bytes()).to_bytes()
        extensions += Extension(extension_type=ExtensionType.SERVER_NAME.value,extension_data=server_name).to_bytes()
    
    
        named_group_list = NamedGroupList(named_group_list=NamedGroup.X25519.value).to_bytes()
        extensions += Extension(extension_type=ExtensionType.SUPPORTED_GROUPS.value,extension_data=named_group_list).to_bytes()
        
        supported_signature_algorithms = (SignatureScheme.ecdsa_secp256r1_sha256.value + SignatureScheme.ecdsa_secp384r1_sha384.value +
                                SignatureScheme.ecdsa_secp521r1_sha512.value + SignatureScheme.ed25519.value + 
                                SignatureScheme.ed448.value + SignatureScheme.rsa_pss_pss_sha256.value + 
                                SignatureScheme.rsa_pss_pss_sha384.value + SignatureScheme.rsa_pss_pss_sha512.value + 
                                SignatureScheme.rsa_pss_rsae_sha256.value +
                                SignatureScheme.rsa_pss_rsae_sha384.value + SignatureScheme.rsa_pss_rsae_sha512.value + 
                                SignatureScheme.rsa_pkcs1_sha256.value + SignatureScheme.rsa_pkcs1_sha384.value +
                                SignatureScheme.rsa_pkcs1_sha512.value)
        signature_scheme_list = SignatureSchemeList(supported_signature_algorithms=supported_signature_algorithms).to_bytes()
        extensions += Extension(extension_type=ExtensionType.SIGNATURE_ALGORITHMS.value,extension_data=signature_scheme_list).to_bytes()
        
        #Them supported_versions:
        supported_versions = SupportedVersions().to_bytes()
        extensions += Extension(extension_type=ExtensionType.SUPPORTED_VERSIONS.value,extension_data=supported_versions).to_bytes()
        
        #Tạo key share:
        key_share_entry = KeyShareEntry(key_exchange=share_key)
        key_share_client_hello = KeyShareClientHello(client_share=key_share_entry).to_bytes()

        extensions += Extension(extension_type=ExtensionType.KEY_SHARE.value,extension_data=key_share_client_hello).to_bytes()
        
        return extensions
    
def gen_client_hello(share_key):
    body = ClientHello(extension=gen_client_hello_extension(share_key)).to_bytes()
    fragment = Handshake(HandshakeType.CLIENT_HELLO.value,body).to_bytes()
    tls_plaintext = TLSPlaintext(ContentType.HANDSHAKE.value,b'\x03\x03',fragment).to_bytes()
    return tls_plaintext