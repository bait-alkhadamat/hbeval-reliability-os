import json
import hmac
import hashlib
import base64
from fastapi import FastAPI, Request, HTTPException, Header
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI(title="HB-Eval Gateway - Stable")

API_KEY = "hb_prod_132182Q"
AES_KEY_B64 = "ribUleLD81UmgG0tNBWijC0P2OPx6zRPBTrwvavE/kI="
AES_KEY = base64.b64decode(AES_KEY_B64)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/evaluate")
async def evaluate(
    request: Request,
    authorization: str = Header(None),
    x_hbeval_nonce: str = Header(None),
    x_hbeval_timestamp: str = Header(None),
    x_hbeval_signature: str = Header(None)
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing auth")
    token = authorization.split(" ")[1]
    if token != API_KEY:
        raise HTTPException(401, "Invalid API Key")
    
    expected = hmac.new(
        hashlib.sha256(API_KEY.encode()).digest(),
        f"{x_hbeval_timestamp}.{x_hbeval_nonce}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, x_hbeval_signature):
        raise HTTPException(401, "Invalid signature")
    
    body = await request.json()
    ciphertext = bytes.fromhex(body["ciphertext"])
    aesgcm = AESGCM(AES_KEY)
    decrypted = aesgcm.decrypt(x_hbeval_nonce.encode(), ciphertext, None)
    payload = json.loads(decrypted.decode())
    print("Received:", payload)
    
    # رد ثابت (ناجح)
    return {
        "verdict": "SAFE",
        "metrics": {
            "pei": 0.95,
            "irs": 0.98
        }
    }
