from fastapi import FastAPI, Request

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok", "message": "Gateway is live"}

@app.post("/evaluate")
async def evaluate(request: Request):
    body = await request.json()
    # فقط أعد رد ثابت
    return {"verdict": "SAFE", "metrics": {"pei": 0.99, "irs": 0.99}}
