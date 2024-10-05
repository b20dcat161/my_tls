from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from dataclasses import dataclass
import hashlib
import hmac
import struct
import binascii
from binascii import hexlify
# TODO: delete
def hex_to_bytes(hex_string):
    hex_string = hex_string.replace("\n", "").replace(" ", "")
    
    byte_string = binascii.unhexlify(hex_string)
    
    return byte_string

def hkdf_extract(salt, ikm, hash_algorithm=hashes.SHA384):
    if not salt:
        salt = bytes(48)
    return hmac.new(salt, ikm, hash_algorithm().name).digest()

def hkdf_expand(prk, info, length, hash_algorithm=hashes.SHA384):
    hkdf = HKDFExpand(
        algorithm=hash_algorithm(),
        length=length,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(prk)

def hkdf_expand_label(secret, label: bytes, context, length, hash_algorithm=hashes.SHA384):
    tls13_label = b"tls13 " + label
    hkdf_label = length.to_bytes(2, byteorder='big') + \
                 len(tls13_label).to_bytes(1, byteorder='big') + tls13_label + \
                 len(context).to_bytes(1, byteorder='big') + context
    return hkdf_expand(secret, hkdf_label, length, hash_algorithm)
@dataclass 
class HandshakeKeys:
    client_key: bytes
    client_iv: bytes
    client_handshake_traffic_secret: bytes
    server_key: bytes
    server_iv: bytes
    server_handshake_traffic_secret: bytes
    handshake_secret: bytes

@dataclass
class ApplicationKeys:
    client_key: bytes
    client_iv: bytes
    server_key: bytes
    server_iv: bytes
    master_secret: bytes
@dataclass
class KeyPair:
    private_key: X25519PrivateKey = X25519PrivateKey.generate()
    
    def calc_hanshake_keys(self, shared_secret: bytes, hello_hash):
        # early_secret = HKDF-Extract(salt: 00, key: 00...)
        print('hello_hash',hello_hash.hex())
        early_secret = hkdf_extract(b'\x00',b'\x00'*48)
        # empty_hash = SHA384("")
        empty_hash = hashlib.sha384(b'').digest()
        # derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
        derived_secret = hkdf_expand_label(early_secret, b'derived',empty_hash,48)
        # handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)
        handshake_secret = hkdf_extract(derived_secret,shared_secret)
        # client_secret = HKDF-Expand-Label(key: handshake_secret, label: "c hs traffic", ctx: hello_hash, len: 48)
        client_secret = hkdf_expand_label(handshake_secret, b'c hs traffic', hello_hash, 48)
        # server_secret = HKDF-Expand-Label(key: handshake_secret, label: "s hs traffic", ctx: hello_hash, len: 48)
        server_secret = hkdf_expand_label(handshake_secret, b's hs traffic', hello_hash, 48)
        
        # client_handshake_key = HKDF-Expand-Label(key: client_secret, label: "key", ctx: "", len: 32)
        # server_handshake_key = HKDF-Expand-Label(key: server_secret, label: "key", ctx: "", len: 32)
        # client_handshake_iv = HKDF-Expand-Label(key: client_secret, label: "iv", ctx: "", len: 12)
        # server_handshake_iv = HKDF-Expand-Label(key: server_secret, label: "iv", ctx: "", len: 12)
        c_hs_key = hkdf_expand_label(client_secret, b'key', b'', 32)
        s_hs_key = hkdf_expand_label(server_secret, b'key', b'', 32)
        c_hs_iv = hkdf_expand_label(client_secret, b'iv', b'', 12)
        s_hs_iv = hkdf_expand_label(server_secret, b'iv', b'', 12)
        print(c_hs_key.hex(), s_hs_key.hex(), c_hs_iv.hex(), s_hs_iv.hex())
        
        return HandshakeKeys(
            client_key=c_hs_key,
            client_iv=c_hs_iv,
            client_handshake_traffic_secret=client_secret,
            server_key=s_hs_key,
            server_iv=s_hs_iv,
            server_handshake_traffic_secret=server_secret,
            handshake_secret=handshake_secret,
        )
        
    def calc_ap_keys(self,handshake_secret, handshake_hash):
        # empty_hash = SHA384("")
        empty_hash = hashlib.sha384(b'').digest()
        # derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
        derived_secret = hkdf_expand_label(handshake_secret, b'derived',empty_hash,48)
        # master_secret = HKDF-Extract(salt: derived_secret, key: 00...)
        master_secret = hkdf_extract(derived_secret,b'\x00'*48)
        print('master secret',master_secret.hex())
        # client_secret = HKDF-Expand-Label(key: master_secret, label: "c ap traffic", ctx: handshake_hash, len: 48)
        # server_secret = HKDF-Expand-Label(key: master_secret, label: "s ap traffic", ctx: handshake_hash, len: 48)
        client_secret = hkdf_expand_label(master_secret, b'c ap traffic', handshake_hash, 48)
        print(client_secret.hex())
        server_secret = hkdf_expand_label(master_secret, b's ap traffic', handshake_hash, 48)
        
        # client_handshake_key = HKDF-Expand-Label(key: client_secret, label: "key", ctx: "", len: 32)
        # server_handshake_key = HKDF-Expand-Label(key: server_secret, label: "key", ctx: "", len: 32)
        # client_handshake_iv = HKDF-Expand-Label(key: client_secret, label: "iv", ctx: "", len: 12)
        # server_handshake_iv = HKDF-Expand-Label(key: server_secret, label: "iv", ctx: "", len: 12)
        c_ap_key = hkdf_expand_label(client_secret, b'key', b'', 32)
        s_ap_key = hkdf_expand_label(server_secret, b'key', b'', 32)
        c_ap_iv = hkdf_expand_label(client_secret, b'iv', b'', 12)
        s_ap_iv = hkdf_expand_label(server_secret, b'iv', b'', 12)
        print(c_ap_key.hex(), s_ap_key.hex(), c_ap_iv.hex(), s_ap_iv.hex())
        
        return ApplicationKeys(
            client_key=c_ap_key,
            client_iv=c_ap_iv,
            server_key=s_ap_key,
            server_iv=s_ap_iv,
            master_secret=master_secret
        )
    def gen_public(self):
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        return public_bytes
    def exchange(self, peer_pub_key_bytes: bytes) -> bytes:
        peer_pub_key = X25519PublicKey.from_public_bytes(peer_pub_key_bytes)
        #TODO : change
        shared_key = self.private_key.exchange(peer_pub_key)
        # shared_key = hex_to_bytes('df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624')
        return shared_key

def build_iv(iv, record_num: int):
    record_num_bytes = bytearray(record_num.to_bytes(8,'big'))
    iv = bytearray(iv)
    for i in range(8):
        iv[12 - 1 - i] ^= record_num_bytes[8-1-i]
    return bytes(iv)
    
def decrypt_aes_gcm(iv, record_num, key, record, ciphertext, auth_tag):
    iv = build_iv(iv,record_num)

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, auth_tag), backend=backend)
    decryptor = cipher.decryptor()

    decryptor.authenticate_additional_data(record)

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        print(e)
        
        
def encrypt_aes_gcm(iv, record_num, key, record, plaintex):
    iv = build_iv(iv,record_num)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(record)
    ciphertext = encryptor.update(plaintex) + encryptor.finalize()
    return ciphertext+encryptor.tag


