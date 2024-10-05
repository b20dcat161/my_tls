
from socket import socket
from dataclasses import dataclass, field
from client_hello import *
from cypto import *
import hashlib
from io import BytesIO, BufferedReader
from extension import *
import ssl
import binascii
def hex_to_bytes(hex_string):
    hex_string = hex_string.replace("\n", "").replace(" ", "")
    
    byte_string = binascii.unhexlify(hex_string)
    
    return byte_string
@dataclass
class TLSSession:
    host : str = 'ghtk.me'
    port : int = 443
    hello_msg: bytearray = b''
    key_pair = KeyPair()
    hs_send_counter: int  = 0
    hs_recv_counter: int  = 0
    ap_send_counter: int  = 0
    ap_recv_counter: int  = 0
    socket = socket()
    hs_keys: HandshakeKeys = None
    def send_client_hello(self):
        share_key = self.key_pair.gen_public()
        # TODO: 
        client_hello = gen_client_hello(share_key)
        # client_hello = hex_to_bytes('''16 03 01 00 f8 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54''')
        
        self.hello_msg += client_hello[5:]
        self.socket.sendall(client_hello)
       
    def recv_server_hello(self, bytes_buffer: BufferedReader):
        org_buffer = bytes_buffer.peek()
        record_header = bytes_buffer.read(5)
        handshake_header = bytes_buffer.read(4)
        self.hello_msg += org_buffer[5:5+int.from_bytes(record_header[3:5])]
        print('len hello:',len(self.hello_msg))
        server_version = bytes_buffer.read(2)
        server_random = bytes_buffer.read(32)
        session_id_length = int.from_bytes(bytes_buffer.read(1),'big')
        session_id = bytes_buffer.read(session_id_length)
        cipher_suite = bytes_buffer.read(2)
        print('cipher suite: ',cipher_suite)
        compression_mode = bytes_buffer.read(1)
        extensions_length = int.from_bytes(bytes_buffer.read(2))
        
        while extensions_length > 0:
            type = int.from_bytes(bytes_buffer.read(2))
            length = int.from_bytes(bytes_buffer.read(2))
            data = bytes_buffer.read(length)
            extensions_length -= length+4
            if type == ExtensionType.SUPPORTED_VERSIONS.value:
                print('Suported Version: ', data)
            if type == ExtensionType.KEY_SHARE.value:
                print('Key share extension')
                print('Group', data[:2])
                print('Key exchange length: ',int.from_bytes(data[2:4]))
                print('Key exchange ', data[4:].hex())
                shared_secret = self.key_pair.exchange(data[4:])
                print('shared secret: ',shared_secret.hex())
                hello_hash = hashlib.sha384(self.hello_msg).digest()
                self.hs_keys = self.key_pair.calc_hanshake_keys(shared_secret,hello_hash)


    def recv_change_cipher_spec(self, bytes_buffer: BufferedReader):
        header = bytes_buffer.read(5)
        (content_type,version, length) = record_header_handler(header)
        print('content_type, version: ', content_type,version)
        fragment = bytes_buffer.read(length)
        return header+fragment
        
    def recv_encrypted_data(self, bytes_buffer: BufferedReader):
        record_header = bytes_buffer.read(5)
        (content_type,version, length) = record_header_handler(record_header)
        print('content_type, version: ', content_type,version)
        print(length)
        encrypted_data = bytes_buffer.read(length-16)
        auth_tag = bytes_buffer.read(16)
        return decrypt_aes_gcm(
            self.hs_keys.server_iv,
            self.hs_recv_counter,
            self.hs_keys.server_key,
            record_header,encrypted_data,auth_tag)
        
    def recv_application_data(self, bytes_buffer: BufferedReader):
        record_header = bytes_buffer.read(5)
        (content_type,version, length) = record_header_handler(record_header)
        print('content_type, version: ', content_type,version)
        print(length)
        encrypted_data = bytes_buffer.read(length-16)
        auth_tag = bytes_buffer.read(16)
        return decrypt_aes_gcm(
            self.application_keys.server_iv,
            self.ap_recv_counter,
            self.application_keys.server_key,
            record_header,encrypted_data,auth_tag)
    def explorer_data(self,plain_text):
        msg_type = int.from_bytes(plain_text[:1])
        print(HandshakeType(msg_type).name)
        

    def send_handshake_finished(self, handshake_hash):
        finished_key = hkdf_expand_label(self.hs_keys.client_handshake_traffic_secret, b'finished', b'',48)
        verify_data = hmac.new(
            finished_key, handshake_hash,digestmod=hashlib.sha384
        ).digest() 
        plain_text = b'\x14\x00\x00\x30'+ verify_data + b'\x16'

        record_header = b'\x17\x03\x03\x00\x45'
        fragment = encrypt_aes_gcm(
            self.hs_keys.client_iv,
            self.hs_send_counter,
            self.hs_keys.client_key,
            record_header,plain_text)
        self.hs_send_counter += 1
        tls_ciphertext = record_header + fragment
        # TODO
        # print(tls_ciphertext.hex())
        self.socket.sendall(tls_ciphertext)
    
    
    
    def connect(self) -> None:
        self.socket.connect((self.host,self.port))
        self.send_client_hello()
        #TODO
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(40960)))
        res = '''16 03 03 00 7a 02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15'''
        res += '''14 03 03 00 01 01'''
        res += '17 03 03 00 17 6b e0 2f 9d a7 c2 dc 9d de f5 6f 24 68 b9 0a df a2 51 01 ab 03 44 ae'
        res +=' 17 03 03 03 43 ba f0 0a 9b e5 0f 3f 23 07 e7 26 ed cb da cb e4 b1 86 16 44 9d 46 c6 20 7a f6 e9 95 3e e5 d2 41 1b a6 5d 31 fe af 4f 78 76 4f 2d 69 39 87 18 6c c0 13 29 c1 87 a5 e4 60 8e 8d 27 b3 18 e9 8d d9 47 69 f7 73 9c e6 76 83 92 ca ca 8d cc 59 7d 77 ec 0d 12 72 23 37 85 f6 e6 9d 6f 43 ef fa 8e 79 05 ed fd c4 03 7e ee 59 33 e9 90 a7 97 2f 20 69 13 a3 1e 8d 04 93 13 66 d3 d8 bc d6 a4 a4 d6 47 dd 4b d8 0b 0f f8 63 ce 35 54 83 3d 74 4c f0 e0 b9 c0 7c ae 72 6d d2 3f 99 53 df 1f 1c e3 ac eb 3b 72 30 87 1e 92 31 0c fb 2b 09 84 86 f4 35 38 f8 e8 2d 84 04 e5 c6 c2 5f 66 a6 2e be 3c 5f 26 23 26 40 e2 0a 76 91 75 ef 83 48 3c d8 1e 6c b1 6e 78 df ad 4c 1b 71 4b 04 b4 5f 6a c8 d1 06 5a d1 8c 13 45 1c 90 55 c4 7d a3 00 f9 35 36 ea 56 f5 31 98 6d 64 92 77 53 93 c4 cc b0 95 46 70 92 a0 ec 0b 43 ed 7a 06 87 cb 47 0c e3 50 91 7b 0a c3 0c 6e 5c 24 72 5a 78 c4 5f 9f 5f 29 b6 62 68 67 f6 f7 9c e0 54 27 35 47 b3 6d f0 30 bd 24 af 10 d6 32 db a5 4f c4 e8 90 bd 05 86 92 8c 02 06 ca 2e 28 e4 4e 22 7a 2d 50 63 19 59 35 df 38 da 89 36 09 2e ef 01 e8 4c ad 2e 49 d6 2e 47 0a 6c 77 45 f6 25 ec 39 e4 fc 23 32 9c 79 d1 17 28 76 80 7c 36 d7 36 ba 42 bb 69 b0 04 ff 55 f9 38 50 dc 33 c1 f9 8a bb 92 85 83 24 c7 6f f1 eb 08 5d b3 c1 fc 50 f7 4e c0 44 42 e6 22 97 3e a7 07 43 41 87 94 c3 88 14 0b b4 92 d6 29 4a 05 40 e5 a5 9c fa e6 0b a0 f1 48 99 fc a7 13 33 31 5e a0 83 a6 8e 1d 7c 1e 4c dc 2f 56 bc d6 11 96 81 a4 ad bc 1b bf 42 af d8 06 c3 cb d4 2a 07 6f 54 5d ee 4e 11 8d 0b 39 67 54 be 2b 04 2a 68 5d d4 72 7e 89 c0 38 6a 94 d3 cd 6e cb 98 20 e9 d4 9a fe ed 66 c4 7e 6f c2 43 ea be bb cb 0b 02 45 38 77 f5 ac 5d bf bd f8 db 10 52 a3 c9 94 b2 24 cd 9a aa f5 6b 02 6b b9 ef a2 e0 13 02 b3 64 01 ab 64 94 e7 01 8d 6e 5b 57 3b d3 8b ce f0 23 b1 fc 92 94 6b bc a0 20 9c a5 fa 92 6b 49 70 b1 00 91 03 64 5c b1 fc fe 55 23 11 ff 73 05 58 98 43 70 03 8f d2 cc e2 a9 1f c7 4d 6f 3e 3e a9 f8 43 ee d3 56 f6 f8 2d 35 d0 3b c2 4b 81 b5 8c eb 1a 43 ec 94 37 e6 f1 e5 0e b6 f5 55 e3 21 fd 67 c8 33 2e b1 b8 32 aa 8d 79 5a 27 d4 79 c6 e2 7d 5a 61 03 46 83 89 19 03 f6 64 21 d0 94 e1 b0 0a 9a 13 8d 86 1e 6f 78 a2 0a d3 e1 58 00 54 d2 e3 05 25 3c 71 3a 02 fe 1e 28 de ee 73 36 24 6f 6a e3 43 31 80 6b 46 b4 7b 83 3c 39 b9 d3 1c d3 00 c2 a6 ed 83 13 99 77 6d 07 f5 70 ea f0 05 9a 2c 68 a5 f3 ae 16 b6 17 40 4a f7 b7 23 1a 4d 94 27 58 fc 02 0b 3f 23 ee 8c 15 e3 60 44 cf d6 7c d6 40 99 3b 16 20 75 97 fb f3 85 ea 7a 4d 99 e8 d4 56 ff 83 d4 1f 7b 8b 4f 06 9b 02 8a 2a 63 a9 19 a7 0e 3a 10 e3 08 41 58 fa a5 ba fa 30 18 6c 6b 2f 23 8e b5 30 c7 3e'
        res += '17 03 03 01 19 73 71 9f ce 07 ec 2f 6d 3b ba 02 92 a0 d4 0b 27 70 c0 6a 27 17 99 a5 33 14 f6 f7 7f c9 5c 5f e7 b9 a4 32 9f d9 54 8c 67 0e be ea 2f 2d 5c 35 1d d9 35 6e f2 dc d5 2e b1 37 bd 3a 67 65 22 f8 cd 0f b7 56 07 89 ad 7b 0e 3c ab a2 e3 7e 6b 41 99 c6 79 3b 33 46 ed 46 cf 74 0a 9f a1 fe c4 14 dc 71 5c 41 5c 60 e5 75 70 3c e6 a3 4b 70 b5 19 1a a6 a6 1a 18 fa ff 21 6c 68 7a d8 d1 7e 12 a7 e9 99 15 a6 11 bf c1 a2 be fc 15 e6 e9 4d 78 46 42 e6 82 fd 17 38 2a 34 8c 30 10 56 b9 40 c9 84 72 00 40 8b ec 56 c8 1e a3 d7 21 7a b8 e8 5a 88 71 53 95 89 9c 90 58 7f 72 e8 dd d7 4b 26 d8 ed c1 c7 c8 37 d9 f2 eb bc 26 09 62 21 90 38 b0 56 54 a6 3a 0b 12 99 9b 4a 83 06 a3 dd cc 0e 17 c5 3b a8 f9 c8 03 63 f7 84 13 54 d2 91 b4 ac e0 c0 f3 30 c0 fc d5 aa 9d ee f9 69 ae 8a b2 d9 8d a8 8e bb 6e a8 0a 3a 11 f0 0e a2 96 a3 23 23 67 ff 07 5e 1c 66 dd 9c be dc 47 13'
        res += '17 03 03 00 45 10 61 de 27 e5 1c 2c 9f 34 29 11 80 6f 28 2b 71 0c 10 63 2c a5 00 67 55 88 0d bf 70 06 00 2d 0e 84 fe d9 ad f2 7a 43 b5 19 23 03 e4 df 5c 28 5d 58 e3 c7 62 24 07 84 40 c0 74 23 74 74 4a ec f2 8c f3 18 2f d0'
        
        # bytes_buffer = BufferedReader(BytesIO(hex_to_bytes(res)))
        self.recv_server_hello(bytes_buffer)
        change_cipher_spec = self.recv_change_cipher_spec(bytes_buffer)
        
        
        # sv encrypted extension
        plaintext = self.recv_encrypted_data(bytes_buffer)
        # print('plaint text: ',plaintext)
        self.explorer_data(plaintext)
        self.hs_recv_counter += 1
        self.hello_msg += plaintext[:-1]
        # sv cert
        plaintext = self.recv_encrypted_data(bytes_buffer)
        # print('plaint text: ',plaintext) 
        self.explorer_data(plaintext)
        self.hs_recv_counter += 1
        self.hello_msg += plaintext[:-1]
        #sv cert auth
        plaintext = self.recv_encrypted_data(bytes_buffer)
        # print('plaint text: ',plaintext) 
        self.explorer_data(plaintext)
        self.hs_recv_counter += 1
        self.hello_msg += plaintext[:-1]
        
    
        #finished
        plaintext = self.recv_encrypted_data(bytes_buffer)
        # print('plaint text: ',plaintext) 
        self.explorer_data(plaintext)
        self.hs_recv_counter += 1
        self.hello_msg += plaintext[:-1]
        data = '01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 00 08 13 02 13 03 13 01 00 ff 01 00 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 00 0b 00 04 03 00 01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04 00 23 00 00 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02 03 04 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54'
        data += '02 00 00 76 03 03 70 71 72 73 74 75 76 77 78 79 7a 7b 7c 7d 7e 7f 80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 20 e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 ea eb ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff 13 02 00 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15'
        
        data += '08 00 00 02 00 00'
        data += '0b 00 03 2e 00 00 03 2a 00 03 25 30 82 03 21 30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0 00 00'
        data += '''0f 00 01 04 08 04 01 00 5c bb 24 c0 40 93 32 da a9 20 bb ab bd b9 bd 50 17 0b e4 9c fb e0 a4 10 7f ca 6f fb 10 68 e6 5f 96 9e 6d e7 d4 f9 e5 60 38 d6 7c 69 c0 31 40 3a 7a 7c 0b cc 86 83 e6 57 21 a0 c7 2c c6 63 40 19 ad 1d 3a d2 65 a8 12 61 5b a3 63 80 37 20 84 f5 da ec 7e 63 d3 f4 93 3f 27 22 74 19 a6 11 03 46 44 dc db c7 be 3e 74 ff ac 47 3f aa ad de 8c 2f c6 5f 32 65 77 3e 7e 62 de 33 86 1f a7 05 d1 9c 50 6e 89 6c 8d 82 f5 bc f3 5f ec e2 59 b7 15 38 11 5e 9c 8c fb a6 2e 49 bb 84 74 f5 85 87 b1 1b 8a e3 17 c6 33 e9 c7 6c 79 1d 46 62 84 ad 9c 4f f7 35 a6 d2 e9 63 b5 9b bc a4 40 a3 07 09 1a 1b 4e 46 bc c7 a2 f9 fb 2f 1c 89 8e cb 19 91 8b e4 12 1d 7e 8e d0 4c d5 0c 9a 59 e9 87 98 01 07 bb bf 29 9c 23 2e 7f db e1 0a 4c fd ae 5c 89 1c 96 af df f9 4b 54 cc d2 bc 19 d3 cd aa 66 44 85 9c'''
        data += '14 00 00 30 7e 30 ee cc b6 b2 3b e6 c6 ca 36 39 92 e8 42 da 87 7e e6 47 15 ae 7f c0 cf 87 f9 e5 03 21 82 b5 bb 48 d1 e3 3f 99 79 05 5a 16 0c 8d bb b1 56 9c'
        
        # self.hello_msg = hex_to_bytes(data)
        handshake_hash = hashlib.sha384(self.hello_msg).digest()
        
        print('handshake hash: ',handshake_hash.hex(), hashlib.sha384(hex_to_bytes(data)).digest().hex())
        self.application_keys = self.key_pair.calc_ap_keys(
            self.hs_keys.handshake_secret, handshake_hash
        )
        #TODO
        self.socket.sendall(change_cipher_spec)
        self.send_handshake_finished(handshake_hash)
        # bytes_buffer = BufferedReader(
        #         BytesIO(bytes_buffer.read() + self.socket.recv(4096)))
        # plaintext = self.recv_encrypted_data(bytes_buffer)
        # print('plaint text: ',plaintext) 
        # self.explorer_data(plaintext)
        
    def send(self,data):
        plain_text = data + b'\x17'
        record_header = b'\x17' + b'\x03\x03' + (len(plain_text)+16).to_bytes(2,'big')
        fragment = encrypt_aes_gcm(
            self.application_keys.client_iv,
            self.ap_send_counter,
            self.application_keys.client_key,
            record_header,plain_text)
        self.ap_send_counter += 1
        self.socket.sendall(record_header+fragment)
        
        
    def recv(self):
        bytes_buffer = BufferedReader(BytesIO(self.socket.recv(40960)))
        if len(bytes_buffer.peek()) < 4:
            bytes_buffer = BufferedReader(
                BytesIO(bytes_buffer.read() + self.socket.recv(40960))
            )
        plaint_text = self.recv_application_data(bytes_buffer)
        self.ap_recv_counter +=1
        print(plaint_text.hex())
        
        print('continue...')
        
        plaint_text = self.recv_application_data(bytes_buffer)
        self.ap_recv_counter +=1
        print(plaint_text.hex())
        
        print('continue...')
        bytes_buffer = BufferedReader(
            BytesIO(bytes_buffer.read() + self.socket.recv(4096))
        )
        
        plaint_text = self.recv_application_data(bytes_buffer)
        self.ap_recv_counter +=1
        print(plaint_text.hex())
        
        return plaint_text
        
def record_header_handler(header: bytes):
    return (int.from_bytes(header[:1]),header[1:3],int.from_bytes(header[3:])) #(content_type,version,fragment_length)

def handshake_header_handler(header: bytes):
    return (int.from_bytes(header[:1]),int.from_bytes(header[1:4])) #(msg_type,body_length)