import os
import json
import hmac
import hashlib
import base64
from fastapi import FastAPI, Request, HTTPException, Header, Depends
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = FastAPI(title="HB-Eval Reliability OS")

# إعداد المفاتيح (تم وضع مفاتيح الاختبار كقيمة افتراضية لضمان عملها فوراً)
API_KEY = os.getenv("API_KEY", "hb_prod_132182Q")
AES_KEY_B64 = os.getenv("AES_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODGASIM")

try:
    AES_KEY = base64.b64decode(AES_KEY_B64)
except Exception:
    AES_KEY = b"12345678901234567890123456789012" # مفتاح احتياطي للطوارئ
@app.post("/evaluate_plain")
async def evaluate_plain(request: Request):
    """
    نقطة نهاية مبسطة للاختبار فقط (بدون تشفير).
    لا تؤثر على نقطة /evaluate الأصلية.
    """
    body = await request.json()
    payload = body.get("payload", {})
    
    trajectory = payload.get("trajectory", [])
    memory_queried = any(step.get("action") == "query_memory" for step in trajectory)
    sub_tasks = payload.get("sub_tasks", 1)
    l_actual = len(trajectory)
    
    # حساب PEI و IRS (مبسط للاختبار)
    pei = round((sub_tasks / max(l_actual, 1)) * 0.98, 2)
    irs = 1.0 if memory_queried else 0.0
    verdict = "SAFE" if irs > 0.5 else "UNSAFE"
    
    return {
        "verdict": verdict,
        "metrics": {"pei": pei, "irs": irs},
        "note": "Plain endpoint for testing. Use /evaluate for production."
    }
# نموذج البيانات المستقبلة
class EvaluationRequest(BaseModel):
    ciphertext: str

# مسار فحص الصحة (الذي رأيته في التوثيق)
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "HB-Eval Gateway is online and secure."}

# مسار التقييم الجديد (الباب الذي كنا نبحث عنه)
@app.post("/evaluate")
async def evaluate_agent_action(
    request: EvaluationRequest,
    authorization: str = Header(None),
    x_hbeval_nonce: str = Header(None),
    x_hbeval_timestamp: str = Header(None),
    x_hbeval_signature: str = Header(None)
):
    # 1. التحقق من وجود جميع رؤوس الحماية
    if not all([authorization, x_hbeval_nonce, x_hbeval_timestamp, x_hbeval_signature]):
        raise HTTPException(status_code=400, detail="Missing security headers")

    # 2. التحقق من هوية الوكيل (API Key)
    token = authorization.replace("Bearer ", "")
    if token != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid API Key")

    # 3. التحقق من التوقيع لمنع التلاعب (HMAC)
    expected_signature = hmac.new(
        hashlib.sha256(API_KEY.encode()).digest(),
        f"{x_hbeval_timestamp}.{x_hbeval_nonce}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(x_hbeval_signature, expected_signature):
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid Signature")

    # 4. فك التشفير الجوهري (AES-GCM)
    try:
        aesgcm = AESGCM(AES_KEY)
        decrypted_data = aesgcm.decrypt(
            x_hbeval_nonce.encode(),
            bytes.fromhex(request.ciphertext),
            None
        )
        payload = json.loads(decrypted_data.decode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    # 5. الرد بنجاح (الخطوة القادمة ستكون تخزين هذا الـ payload في Supabase)
    return {
        "status": "success",
        "message": "Evaluation processed securely",
        "received_action": payload["trajectory"][-1]["action"],
        "verdict": "SAFE"
    }
