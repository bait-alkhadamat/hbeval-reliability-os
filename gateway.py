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

# ---------- App initialization ----------
app = FastAPI(title="HB-Eval Reliability OS", version="2.0.0")

# ---------- Environment variables ----------
# إعداد المفاتيح (تم وضع مفاتيح الاختبار كقيمة افتراضية لضمان عملها فوراً)
API_KEY = os.getenv("API_KEY", "hb_prod_132182Q")
AES_KEY_B64 = os.getenv("AES_KEY", "ribUleLD81UmgG0tNBWijC0P2OPx6zRPBTrwvavE/kI=")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

try:
    AES_KEY = base64.b64decode(AES_KEY_B64)
except Exception:
    AES_KEY = b"12345678901234567890123456789012"

# ---------- Supabase client ----------
supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Supabase connected")
else:
    print("⚠️ Supabase not configured – storage disabled")

# ---------- Embeddings (lazy load for EDM) ----------
_embedding_model = None
def get_embedding_model():
    global _embedding_model
    if _embedding_model is None:
        from sentence_transformers import SentenceTransformer
        _embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
    return _embedding_model

# ---------- CSI helper ----------
def get_csi_for_agent(project_id: str, agent_id: str = None):
    query = supabase.table("evaluations").select("pei_score, irs_score, verdict").eq("project_id", project_id)
    if agent_id:
        query = query.eq("agent_id", agent_id)
    query = query.order("created_at", desc=True).limit(100)
    evals = query.execute().data
    evals_reversed = list(reversed(evals))
    return HBEvalEngines.calculate_csi_from_history(evals_reversed)

# ---------- Store evaluation and EDM ----------
def store_evaluation_and_edm(project_id: str, agent_id: str, trajectory: list,
                             pei: float, irs: float, verdict: str, context: str,
                             frr: float = 1.0, ti: float = 4.0):
    if not supabase:
        return
    trajectory_hash = hashlib.sha256(json.dumps(trajectory).encode()).hexdigest()
    # Calculate CSI from existing history
    csi = get_csi_for_agent(project_id, agent_id)
    # Insert evaluation
    supabase.table("evaluations").insert({
        "project_id": project_id,
        "agent_id": agent_id,
        "trajectory_hash": trajectory_hash,
        "pei_score": pei,
        "irs_score": irs,
        "csi_score": csi,
        "frr_score": frr,
        "ti_score": ti,
        "verdict": verdict,
        "created_at": datetime.utcnow().isoformat()
    }).execute()
    # Update agent passport (if exists, otherwise create later)
    # Store in EDM only if high quality
    if pei >= 0.8 and irs >= 0.6:
        try:
            embedding = get_embedding_model().encode(context).tolist()
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
            print(f"⚠️ EDM storage failed: {e}")

# ---------- Model for encrypted request ----------
class EvaluationRequest(BaseModel):
    ciphertext: str

# ---------- Health check ----------
@app.get("/health")
def health_check():
    return {"status": "ok", "message": "HB-Eval Gateway is online and secure."}

# ---------- Plain evaluation (testing) ----------
@app.post("/evaluate_plain")
async def evaluate_plain(request: Request):
    body = await request.json()
    payload = body.get("payload", {})
    trajectory = payload.get("trajectory", [])
    sub_tasks = payload.get("sub_tasks", 1)
    violations = payload.get("constraint_violations", 0)
    memory_queried = any(step.get("action") == "query_memory" for step in trajectory)
    recovery_attempts = payload.get("recovery_attempts", 0)
    context = payload.get("context", "General execution")
    agent_id = payload.get("agent_id", "unknown-agent")
    
    pei = HBEvalEngines.calculate_pei(sub_tasks, len(trajectory), violations)
    irs = HBEvalEngines.calculate_irs(memory_queried, recovery_attempts)
    verdict = "SAFE" if (pei >= 0.7 and irs >= 0.6) else "UNSAFE"
    
    project_id = "00000000-0000-0000-0000-000000000001"  # TODO: fetch from API key
    store_evaluation_and_edm(project_id, agent_id, trajectory, pei, irs, verdict, context)
    
    return {
        "verdict": verdict,
        "metrics": {"pei": pei, "irs": irs},
        "note": "Plain evaluation with storage"
    }

# ---------- Encrypted evaluation (production) ----------
@app.post("/evaluate")
async def evaluate_encrypted(
    request: EvaluationRequest,
    authorization: str = Header(None),
    x_hbeval_nonce: str = Header(None),
    x_hbeval_timestamp: str = Header(None),
    x_hbeval_signature: str = Header(None)
):
    # 1. Validate headers
    if not all([authorization, x_hbeval_nonce, x_hbeval_timestamp, x_hbeval_signature]):
        raise HTTPException(status_code=400, detail="Missing security headers")
    
    # 2. API Key check
    token = authorization.replace("Bearer ", "")
    if token != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    # 3. HMAC verification (simplified – add full logic)
    expected_sig = hmac.new(
        hashlib.sha256(API_KEY.encode()).digest(),
        f"{x_hbeval_timestamp}.{x_hbeval_nonce}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(x_hbeval_signature, expected_sig):
        raise HTTPException(status_code=401, detail="Invalid signature")
    
    # 4. Decrypt
    try:
        aesgcm = AESGCM(AES_KEY)
        decrypted = aesgcm.decrypt(
            x_hbeval_nonce.encode(),
            bytes.fromhex(request.ciphertext),
            None
        )
        payload = json.loads(decrypted.decode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")
    
    # 5. Evaluate
    trajectory = payload.get("trajectory", [])
    sub_tasks = payload.get("sub_tasks", 1)
    violations = payload.get("constraint_violations", 0)
    memory_queried = any(step.get("action") == "query_memory" for step in trajectory)
    recovery_attempts = payload.get("recovery_attempts", 0)
    context = payload.get("context", "General execution")
    agent_id = payload.get("agent_id", "unknown-agent")
    
    pei = HBEvalEngines.calculate_pei(sub_tasks, len(trajectory), violations)
    irs = HBEvalEngines.calculate_irs(memory_queried, recovery_attempts)
    verdict = "SAFE" if (pei >= 0.7 and irs >= 0.6) else "UNSAFE"
    
    project_id = "00000000-0000-0000-0000-000000000001"
    store_evaluation_and_edm(project_id, agent_id, trajectory, pei, irs, verdict, context)
    
    return {
        "status": "success",
        "verdict": verdict,
        "metrics": {"pei": pei, "irs": irs}
    }

# ---------- Memory retrieval (semantic) ----------
@app.post("/api/v1/memory/retrieve")
async def retrieve_memory(request: Request):
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase not configured")
    body = await request.json()
    context = body.get("context")
    project_id = body.get("project_id", "00000000-0000-0000-0000-000000000001")
    try:
        query_vec = get_embedding_model().encode(context).tolist()
        response = supabase.rpc("match_edm_memory", {
            "query_embedding": query_vec,
            "match_threshold": 0.75,
            "match_count": 3,
            "p_project_id": project_id
        }).execute()
        return {"status": "success", "matches": response.data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retrieval error: {e}")

# ---------- Agent Passport endpoint ----------
@app.get("/api/v1/agent/{agent_id}")
def get_agent_passport(agent_id: str):
    if not supabase:
        raise HTTPException(status_code=503, detail="Supabase not configured")
    result = supabase.table("agent_passports").select("*").eq("agent_id", agent_id).execute()
    if not result.data:
        # Create minimal record
        supabase.table("agent_passports").insert({
            "agent_id": agent_id,
            "developer_name": "unknown",
            "version": "0.0.0",
            "certification_status": "unverified"
        }).execute()
        return {"agent_id": agent_id, "status": "new"}
    return result.data[0]
