import os
import json
import hmac
import hashlib
import base64
from datetime import datetime
from fastapi import FastAPI, Request, HTTPException, Header
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from supabase import create_client, Client
from engines import HBEvalEngines

app = FastAPI(title="HB-Eval Reliability OS", version="4.0.0")

# ========== البيئة والمفاتيح ==========
API_KEY = os.getenv("API_KEY", "hb_prod_132182Q")
AES_KEY_B64 = os.getenv("AES_KEY", "ribUleLD81UmgG0tNBWijC0P2OPx6zRPBTrwvavE/kI=")
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

try:
    AES_KEY = base64.b64decode(AES_KEY_B64)
except Exception:
    AES_KEY = b"12345678901234567890123456789012"

# ========== Supabase ==========
supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print("✅ Supabase connected")
else:
    print("⚠️ Supabase not configured – storage disabled")

engines = HBEvalEngines()

# ========== دوال مساعدة ==========
def get_csi_for_project(project_id: str):
    """استرجاع آخر التقييمات لحساب CSI"""
    if not supabase:
        return 0.5
    try:
        response = supabase.table("evaluations")\
            .select("pei_score, irs_score, verdict")\
            .eq("project_id", project_id)\
            .order("created_at", desc=True)\
            .limit(100)\
            .execute()
        evals = response.data
        evals_reversed = list(reversed(evals))
        return engines.calculate_csi_from_history(evals_reversed)
    except Exception as e:
        print(f"⚠️ Could not fetch history for CSI: {e}")
        return 0.5

def store_evaluation_and_edm(project_id: str, agent_id: str, trajectory: list,
                             pei: float, irs: float, verdict: str, context: str,
                             total_faults: int = 0, successful_recoveries: int = 0):
    if not supabase:
        return
    
    trajectory_hash = hashlib.sha256(json.dumps(trajectory).encode()).hexdigest()
    
    # حساب المقاييس الإضافية
    frr = engines.calculate_frr(total_faults, successful_recoveries)
    csi = get_csi_for_project(project_id)  # من التاريخ الحالي
    ti = engines.calculate_ti(trajectory)
    
    # تخزين التقييم الكامل
    try:
        supabase.table("evaluations").insert({
            "project_id": project_id,
            "agent_id": agent_id,
            "trajectory_hash": trajectory_hash,
            "pei_score": pei,
            "irs_score": irs,
            "frr_score": frr,
            "csi_score": csi,
            "ti_score": ti,
            "verdict": verdict,
            "created_at": datetime.utcnow().isoformat()
        }).execute()
        print(f"📝 Stored: PEI={pei}, IRS={irs}, FRR={frr}, CSI={csi}, TI={ti}, verdict={verdict}")
    except Exception as e:
        print(f"⚠️ Failed to store evaluation: {e}")
        return
    
    # تخزين في EDM إذا كانت النجاحات ممتازة
    if pei >= 0.8 and irs >= 0.6:
        try:
            supabase.table("edm_memory").insert({
                "project_id": project_id,
                "fault_context": context,
                "trajectory_summary": json.dumps(trajectory),
                "pei_score": pei,
                "irs_score": irs
            }).execute()
            print(f"🧠 Stored in EDM: PEI={pei}, IRS={irs}")
        except Exception as e:
            print(f"⚠️ Failed to store EDM: {e}")

# ========== نقاط النهاية ==========
@app.get("/health")
def health():
    return {"status": "ok", "message": "HB-Eval Gateway (Full Metrics)"}

@app.post("/evaluate")
async def evaluate(
    request: Request,
    authorization: str = Header(None),
    x_hbeval_nonce: str = Header(None),
    x_hbeval_timestamp: str = Header(None),
    x_hbeval_signature: str = Header(None)
):
    # 1. التحقق من الرؤوس
    if not all([authorization, x_hbeval_nonce, x_hbeval_timestamp, x_hbeval_signature]):
        raise HTTPException(400, "Missing security headers")
    token = authorization.replace("Bearer ", "")
    if token != API_KEY:
        raise HTTPException(401, "Invalid API Key")
    
    # 2. التحقق من HMAC
    expected_sig = hmac.new(
        hashlib.sha256(API_KEY.encode()).digest(),
        f"{x_hbeval_timestamp}.{x_hbeval_nonce}".encode(),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(x_hbeval_signature, expected_sig):
        raise HTTPException(401, "Invalid Signature")
    
    # 3. فك التشفير
    body = await request.json()
    ciphertext = body.get("ciphertext")
    if not ciphertext:
        raise HTTPException(400, "Missing ciphertext")
    try:
        aesgcm = AESGCM(AES_KEY)
        decrypted = aesgcm.decrypt(
            x_hbeval_nonce.encode(),
            bytes.fromhex(ciphertext),
            None
        )
        payload = json.loads(decrypted.decode())
    except Exception as e:
        raise HTTPException(400, f"Decryption failed: {e}")
    
    # 4. استخراج البيانات
    trajectory = payload.get("trajectory", [])
    sub_tasks = payload.get("sub_tasks", 1)
    violations = payload.get("constraint_violations", 0)
    memory_queried = any(step.get("action") == "query_memory" for step in trajectory)
    recovery_attempts = payload.get("recovery_attempts", 0)
    context = payload.get("context", "General")
    agent_id = payload.get("agent_id", "unknown")
    total_faults = payload.get("total_faults", 0)
    successful_recoveries = payload.get("successful_recoveries", 0)
    
    # 5. حساب المقاييس الرئيسية
    l_actual = len(trajectory)
    l_min = max(1, sub_tasks)
    pei = engines.calculate_pei(l_min, l_actual, violations)
    irs = engines.calculate_irs(memory_queried, recovery_attempts)
    verdict = "SAFE" if (pei >= 0.7 and irs >= 0.6) else "UNSAFE"
    
    # 6. التخزين (project_id ثابت حالياً)
    project_id = "00000000-0000-0000-0000-000000000001"
    store_evaluation_and_edm(
        project_id, agent_id, trajectory, pei, irs, verdict, context,
        total_faults, successful_recoveries
    )
    
    return {
        "verdict": verdict,
        "metrics": {
            "pei": pei,
            "irs": irs
            # يمكن إضافة المزيد لاحقاً إذا أردت إرجاعها للعميل
        }
    }
