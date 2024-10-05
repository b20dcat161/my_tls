chạy hàm main.py
đây là phần code cho giao thức tls 1.3
Cipher suite: TLS_AES_256_GCM_SHA384
Hàm recv trong tls decrypt liên tiếp 3 data server trả về là server new sessiont ticket 1 và server new session ticket 2, và chỉ return data cuối cùng là https response => có thể chia phần xử lý ra.

Các hướng cần cải thiện code:
* Bổ xung thêm các class: TLSRecord, các class Header, ...
* 1 số gói handshake đang được gửi đi là kiểu string bytes cố định => nếu cần nâng cấp nên code các đối tượng đó.
* 1 số class được code bên git khác(tls)