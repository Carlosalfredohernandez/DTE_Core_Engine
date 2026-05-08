import base64
import sys

data = sys.stdin.read().strip()
decoded = base64.b64decode(data)
print(decoded.decode('latin-1'))
