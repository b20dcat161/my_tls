import subprocess
import re

# Ví dụ lệnh OpenSSL để kết nối tới server
cmd = ['openssl', 's_client', '-connect', 'ghtk.me:443','-msg','-debug']

# Chạy lệnh và thu thập đầu ra
result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# In kết quả đầu ra của OpenSSL
print(result.stdout)

byte_lines = re.findall(r'([0-9a-f]{2}(?: [0-9a-f]{2})*)', result.stdout)
# for line in byte_lines:
#     print(line)
print(byte_lines)