import time
import socket
import ipaddress
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

BASE_DIR = Path(__file__).parent
app = FastAPI(title="HeaderHawk API")

# ==========================================
# 1. KONFIGURASI SCANNER
# ==========================================
SECURITY_HEADERS = {
    "strict-transport-security": 20,
    "content-security-policy": 20,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 15,
    "permissions-policy": 15,
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version"]

class UnsafeURL(Exception):
    pass

def analyze(target_url: str) -> dict:
    # Proteksi SSRF: Cegah scan ke IP lokal / localhost
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https"):
        raise UnsafeURL("URL harus menggunakan http:// atau https://")
    
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeURL("URL tidak valid")
    
    if hostname in ("localhost", "127.0.0.1", "0.0.0.0"):
        raise UnsafeURL("Scanning ke IP lokal tidak diizinkan")
    
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            raise UnsafeURL("Scanning ke IP privat tidak diizinkan")
    except socket.gaierror:
        raise UnsafeURL("Domain tidak dapat ditemukan")

    # Lakukan Scan
    try:
        response = httpx.get(target_url, timeout=10, follow_redirects=True)
    except httpx.HTTPError:
        raise httpx.HTTPError("Gagal mengakses target")

    headers = response.headers
    score = 0
    total_weight = sum(SECURITY_HEADERS.values())
    found_headers = {}
    missing_headers = []
    leaked_info = {}

    # Cek Security Headers
    for header, weight in SECURITY_HEADERS.items():
        if header in headers:
            score += weight
            found_headers[header] = headers[header]
        else:
            missing_headers.append(header)

    # Cek Kebocoran Informasi (Info Leakage)
    for leak_header in INFO_LEAK_HEADERS:
        if leak_header in headers:
            leaked_info[leak_header] = headers[leak_header]

    final_score = int((score / total_weight) * 100)
    
    if final_score >= 90: grade = "A"
    elif final_score >= 75: grade = "B"
    elif final_score >= 60: grade = "C"
    elif final_score >= 40: grade = "D"
    else: grade = "F"

    return {
        "url": target_url,
        "score": final_score,
        "grade": grade,
        "found": found_headers,
        "missing": missing_headers,
        "leaked_info": leaked_info
    }

# ==========================================
# 2. KONFIGURASI API & RATE LIMITING
# ==========================================
RATE_LIMIT = 10
RATE_WINDOW = 60
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
        raise HTTPException(status_code=429, detail="Terlalu banyak permintaan, coba lagi sebentar")
    q.append(now)

@app.get("/")
def read_root():
    index = BASE_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return {"message": "Selamat datang di HeaderHawk API!"}

@app.get("/scan")
def scan_url(url: str, request: Request):
    check_rate_limit(client_ip(request))
    if len(url) > 2048:
        raise HTTPException(status_code=400, detail="URL terlalu panjang")
    
    try:
        result = analyze(url)
    except UnsafeURL as e:
        raise HTTPException(status_code=400, detail=str(e))
    except httpx.HTTPError:
        raise HTTPException(status_code=400, detail="Gagal mengakses target (timeout atau koneksi ditolak)")
        
    return {
        "url": result["url"],
        "score": result["score"],
        "grade": result["grade"],
        "found_headers": result["found"],
        "missing_headers": result["missing"],
        "leaked_info": result["leaked_info"]
    }

@app.get("/dashboard")
def read_dashboard():
    dashboard = BASE_DIR / "dashboard.html"
    if dashboard.exists():
        return FileResponse(dashboard)
    return {"error": "File dashboard.html tidak ditemukan"}
