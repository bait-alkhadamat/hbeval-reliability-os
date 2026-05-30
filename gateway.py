import os
import json
import hmac
import hashlib
import base64
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from supabase import create_client, Client
from engines import HBEvalEngines

# ========== 1. تهيئة التطبيق ==========
app = FastAPI(title="HB-Eval Reliability OS", version="1.0.0")

# ========== 2. قراءة المتغيرات البيئية ==========
API_KEY = os.getenv("API_KEY", "hb_prod_132182Q")
AES_KEY_B64 = os.getenv("AES_KEY", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODGASIM")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
USE_OPENAI_EMBEDDINGS = os.getenv("USE_OPENAI_EMBEDDINGS", "false").lower() == "true"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_EMBEDDING_MODEL = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")

# ========== 3. إعداد مفتاح AES ==========
try:
    AES_KEY = base64.b64decode(AES_KEY_B64)
except Exception:
    AES_KEY = b"12345678901234567890123456789012"

# ========== 4. الاتصال بـ Supabase ==========
supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Supabase connected")
else:
    print("⚠️ Supabase not configured – storage disabled")

# ========== 5. نموذج البيانات المستلمة للتقييم المشفر ==========
class EvaluationRequest(BaseModel):
    ciphertext: str

# ========== 6. Lazy loading for embeddings model ==========
_embedding_model = None
_embedding_model_loaded = False

def get_embedding_model():
    global _embedding_model, _embedding_model_loaded
    if _embedding_model_loaded:
        return _embedding_model
    
    if USE_OPENAI_EMBEDDINGS:
        if not OPENAI_API_KEY:
            raise RuntimeError("OPENAI_API_KEY not set but USE_OPENAI_EMBEDDINGS=true")
        print("✅ Using OpenAI embeddings")
        _embedding_model_loaded = True
        return "openai"
    else:
        try:
            from sentence_transformers import SentenceTransformer
            _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
            print("✅ Local SentenceTransformer loaded")
            _embedding_model_loaded = True
            return _embedding_model
        except ImportError:
            raise RuntimeError("sentence-transformers not installed. Run: pip install sentence-transformers")
        except Exception as e:
            raise RuntimeError(f"Failed to load local embedding model: {e}")

def generate_embedding(text: str):
    model = get_embedding_model()
    if model == "openai":
        import requests
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": OPENAI_EMBEDDING_MODEL,
            "input": text
        }
        resp = requests.post("https://api.openai.com/v1/embeddings", json=data, headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json()["data"][0]["embedding"]
    else:
        return model.encode(text).tolist()

# ========== 7. تخزين التقييم في Supabase و EDM ==========
def store_evaluation_and_edm(project_id: str, trajectory: list, pei: float, irs: float, verdict: str, context: str):
    if not supabase:
        return
    trajectory_hash = hashlib.sha256(json.dumps(trajectory).encode()).hexdigest()
    # insert evaluation
    supabase.table("evaluations").insert({
        "project_id": project_id,
        "trajectory_hash": trajectory_hash,
        "pei_score": pei,
        "irs_score": irs,
        "verdict": verdict,
        "created_at": datetime.utcnow().isoformat()
    }).execute()
    
    # Store in EDM if high quality
    if pei >= 0.8 and irs >= 0.6:
        try:
            embedding = generate_embedding(context)
            supabase.table("edm_memory").insert({
                "project_id": project_id,
                "fault_context": context,
                "trajectory_summary": json.dumps(trajectory),
                "embedding": embedding,
                "pei_score": pei,
                "irs_score": irs
            }).execute()
            print(f"🧠 Stored in EDM: PEI={pei}, IRS={irs}")
        except Exception as e:
            print(f"⚠️ Failed to store EDM: {e}")

# ========== 8. نقطة فحص الصحة ==========
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "HB-Eval Gateway is online and secure."}

# ========== 9. نقطة التقييم المبسطة (بدون تشفير) ==========
@app.post("/evaluate_plain")
async def evaluate_plain(request: Request):
    body = await request.json()
    payload = body.get("payload", {})
    
    trajectory = payload.get("trajectory", [])
    sub_tasks = payload.get("sub_tasks", 1)
    l_actual = len(trajectory)
    l_min = sub_tasks
    violations = payload.get("constraint_violations", 0)
    memory_queried = any(step.get("action") == "query_memory" for step in trajectory)
    recovery_attempts = payload.get("recovery_attempts", 0)
    context = payload.get("context", "General execution")
    
    pei = HBEvalEngines.calculate_pei(l_min, l_actual, violations)
    irs = HBEvalEngines.calculate_irs(memory_queried, recovery_attempts)
    verdict = "SAFE" if (pei >= 0.7 and irs >= 0.6) else "UNSAFE"
    
    # تخزين
    store_evaluation_and_edm("00000000-0000-0000-0000-000000000001", trajectory, pei, irs, verdict, context)
    
    return {
        "verdict": verdict,
        "metrics": {"pei": pei, "irs": irs},
        "note": "Full evaluation with storage (plain endpoint)"
    }

# ========== 10. نقطة التقييم المشفرة (للإنتاج) ==========
@app.post("/evaluate")
async def evaluate_agent_action(
    request: EvaluationRequest,
    authorization: str = Header(None),
    x_hbeval_nonce: str = Header(None),
    x_hbeval_timestamp: str = Header(None),
    x_hbeval_signature: str = Header(None)
):
    # التحقق من الرؤوس الأمنية
    if not all([authorization, x_hbeval_nonce, x_hbeval_timestamp, x_hbeval_signature]):
        raise HTTPException(status_code=400, detail="Missing security headers")
    
    token = authorization.replace("Bearer ", "")
    if token != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    expected_signature = hmac.new(
        hashlib.sha256(API_KEY.encode()).digest(),
        f"{x_hbeval_timestamp}.{x_hbeval_nonce}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(x_hbeval_signature, expected_signature):
        raise HTTPException(status_code=401, detail="Invalid Signature")
    
    # فك التشفير
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
    
    # نفس منطق التقييم
    trajectory = payload.get("trajectory", [])
    sub_tasks = payload.get("sub_tasks", 1)
    l_actual = len(trajectory)
    l_min = sub_tasks
    violations = payload.get("constraint_violations", 0)
    memory_queried = any(step.get("action") == "query_memory" for step in trajectory)
    recovery_attempts = payload.get("recovery_attempts", 0)
    context = payload.get("context", "General execution")
    
    pei = HBEvalEngines.calculate_pei(l_min, l_actual, violations)
    irs = HBEvalEngines.calculate_irs(memory_queried, recovery_attempts)
    verdict = "SAFE" if (pei >= 0.7 and irs >= 0.6) else "UNSAFE"
    
    store_evaluation_and_edm("00000000-0000-0000-0000-000000000001", trajectory, pei, irs, verdict, context)
    
    return {
        "status": "success",
        "verdict": verdict,
        "metrics": {"pei": pei, "irs": irs}
    }

# ========== 11. نقطة استرجاع الذاكرة الدلالية ==========
@app.post("/api/v1/memory/retrieve")
async def retrieve_memory(request: Request):
    body = await request.json()
    context = body.get("context", "")
    project_id = body.get("project_id", "00000000-0000-0000-0000-000000000001")
    
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase not configured")
    
    try:
        query_vec = generate_embedding(context)
        response = supabase.rpc("match_edm_memory", {
            "query_embedding": query_vec,
            "match_threshold": 0.75,
            "match_count": 3,
            "p_project_id": project_id
        }).execute()
        return {"status": "success", "matches": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retrieval failed: {str(e)}")
