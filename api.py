import time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

from scanner import UnsafeURL, analyze

BASE_DIR = Path(__file__).parent
app = FastAPI(title="HeaderHawk API")

RATE_LIMIT = 10   # maksimal request
RATE_WINDOW = 60  # per berapa detik
_hits = defaultdict(deque)


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def check_rate_limit(ip: str) -> None:
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(status_code=429,
                            detail="Terlalu banyak permintaan, coba lagi sebentar")
    q.append(now)


@app.get("/")
def read_root():
    index = BASE_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Selamat datang di HeaderHawk API!"}


@app.get("/scan")
def scan_url(url: str, request: Request):
    """Scan security headers dari URL target via API."""
    check_rate_limit(client_ip(request))
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL terlalu panjang")
    try:
        result = analyze(url)
    except UnsafeURL as e:
        raise HTTPException(status_code=400, detail=str(e))
    except httpx.HTTPError:
        raise HTTPException(
            status_code=400,
            detail="Gagal mengakses target (timeout atau koneksi ditolak)")
    return {
        "url": result["url"],
        "score": result["score"],
        "grade": result["grade"],
        "found_headers": result["found"],
        "missing_headers": result["missing"],
    }
