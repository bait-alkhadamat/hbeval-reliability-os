import os
import json
import time
import hmac
import hashlib
import base64
import redis
from fastapi import FastAPI, Depends, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from sentence_transformers import SentenceTransformer
from supabase import create_client, Client
from engines import HBEvalEngines

app = FastAPI(title="HB-Eval Reliability OS")

# إعداد الاتصالات
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
redis_client = redis.from_url(REDIS_URL, decode_responses=True)
embedding_model = SentenceTransformer('all-MiniLM-L6-v2')

# ---------------------------------------------------------
# ✅ نقطة فحص الصحة (Health Check) - تمت الإضافة بنجاح
# ---------------------------------------------------------
@app.get("/health")
async def health_check():
    try:
        # 1. اختبار اتصال Supabase
        supabase.table('projects').select('id').limit(1).execute()
        # 2. اختبار اتصال Redis
        redis_client.ping()
        # 3. اختبار تحميل محرك الـ Embeddings
        _ = embedding_model.encode("system_warmup_test")
        
        return {"status": "healthy", "services": "supabase, redis, embeddings_engine"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

# ---------------------------------------------------------
# باقي الدوال تعمل كما هي (المصادقة، التقييم، الاسترجاع)
# ---------------------------------------------------------
# async def get_secure_client(...)
# async def verify_security_headers(...)
# @app.post("/api/v1/evaluate")
# @app.post("/api/v1/memory/retrieve")
