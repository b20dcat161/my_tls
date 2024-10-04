from io import BytesIO, BufferedReader

# Tạo một buffer chứa dữ liệu byte
bytes_buffer = BufferedReader(BytesIO(b'Hello, world!'))

# Xem trước 5 byte trong buffer mà không di chuyển con trỏ
peeked_data = bytes_buffer.peek(2)
print(peeked_data)  # Output: b'Hello'
# print(bytes_buffer)
# Kiểm tra vị trí hiện tại của con trỏ
print(bytes_buffer.tell())  # Output: 0 (vẫn ở đầu buffer vì chưa đọc thực sự)

# Bây giờ đọc dữ liệu (lúc này con trỏ sẽ di chuyển)
# read_data = bytes_buffer.read(5)
peeked_data2 = bytes_buffer.peek(2)
print(peeked_data2)  
# print(read_data)  # Output: b'Hello'

# Kiểm tra lại vị trí của con trỏ sau khi đọc
print(bytes_buffer.tell())  # Output: 5 (đã di chuyển sau khi đọc)
