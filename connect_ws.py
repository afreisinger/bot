import jwt
import base64
import datetime
import subprocess
import json
import urllib.request

# =========================
# Config
# =========================
BASE_URL = "http://localhost:8080"
TOKEN_KEY_B64 = "N3M4Q3Z2ZlF4R0tVbWZQYkE5R3R2Z1d1U1F1d2Z5dA=="

# =========================
# Generar JWT
# =========================
key = base64.b64decode(TOKEN_KEY_B64)

payload = {
    "bot": "yes",
    "preferred_username": "web",
    "aud": "bot",
    # comentar esta línea si NO querés expiración
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60)
}

token = jwt.encode(payload, key, algorithm="HS256")

print("\nJWT generado:\n", token)

# =========================
# POST /connector/websocket
# =========================
req = urllib.request.Request(
    f"{BASE_URL}/connector/websocket",
    method="POST",
    headers={
        "Authorization": token,
        "Content-Type": "application/json",
    },
)

with urllib.request.urlopen(req) as resp:
    body = resp.read().decode()
    data = json.loads(body)

socket_id = data["socket"]

print("\nSocket obtenido:\n", socket_id)

# =========================
# Ejecutar wscat
# =========================
ws_url = f"ws://localhost:8080/connector/websocket/{socket_id}"

print("\nConectando vía wscat a:\n", ws_url)
print("\n--- CTRL+C para salir ---\n")

subprocess.run([
    "wscat",
    "-c",
    ws_url
])
