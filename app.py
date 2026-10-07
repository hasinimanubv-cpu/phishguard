"""FastAPI entrypoint for the PhishGuard demo backend. Run: uvicorn app:app --reload"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from detector import detect_indicators
from scoring import build_result

app = FastAPI(title="PhishGuard API", description="Explainable, offline phishing-risk assessment demo.", version="1.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])

class AnalyzeRequest(BaseModel):
    message: str | None = Field(default=None, max_length=20000)
    text: str | None = Field(default=None, max_length=20000, description="Compatibility alias for message")
    url: str | None = Field(default=None, max_length=2048)
    sender: str | None = Field(default=None, max_length=320)
    content_type: str = "auto"

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "phishguard-api"}

@app.post("/api/v1/analyze")
def analyze(request: AnalyzeRequest):
    message = request.message if request.message is not None else (request.text or "")
    if not message.strip() and not (request.url and request.url.strip()):
        raise HTTPException(status_code=422, detail="Provide a non-empty message/text or URL.")
    factors, indicators = detect_indicators(message, request.url, request.sender)
"""FastAPI entrypoint for the PhishGuard demo backend. Run: uvicorn app:app --reload"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from detector import detect_indicators
from scoring import build_result

app = FastAPI(title="PhishGuard API", description="Explainable, offline phishing-risk assessment demo.", version="1.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["*"])

class AnalyzeRequest(BaseModel):
    message: str | None = Field(default=None, max_length=20000)
    text: str | None = Field(default=None, max_length=20000, description="Compatibility alias for message")
    url: str | None = Field(default=None, max_length=2048)
    sender: str | None = Field(default=None, max_length=320)
    content_type: str = "auto"

@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "phishguard-api"}

@app.post("/analyze")
@app.post("/api/v1/analyze")
def analyze(request: AnalyzeRequest):
    message = request.message if request.message is not None else (request.text or "")
    if not message.strip() and not (request.url and request.url.strip()):
        raise HTTPException(status_code=422, detail="Provide a non-empty message/text or URL.")
    factors, indicators = detect_indicators(message, request.url, request.sender)
    return build_result(factors, indicators)
