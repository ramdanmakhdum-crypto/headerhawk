from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
import httpx
import os


app = FastAPI(title="HeaderHawk API")

SECURITY_HEADERS = {
    "strict-transport-security": 20,
    "content-security-policy": 20,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 15,
    "permissions-policy": 15,
}


@app.get("/")
def read_root():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return {"message": "Selamat datang di HeaderHawk API!"}


@app.get("/scan")
def scan_url(url: str):
    """Scan security headers dari URL target via API."""
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        headers = response.headers

        score = 0
        total_weight = sum(SECURITY_HEADERS.values())
        found_headers = {}
        missing_headers = []

        for header, weight in SECURITY_HEADERS.items():
            if header in headers:
                score += weight
                found_headers[header] = headers[header]
            else:
                missing_headers.append(header)

        final_score = int((score / total_weight) * 100)

        if final_score >= 90: grade = "A"
        elif final_score >= 75: grade = "B"
        elif final_score >= 60: grade = "C"
        elif final_score >= 40: grade = "D"
        else: grade = "F"

        return {
            "url": url,
            "score": final_score,
            "grade": grade,
            "found_headers": found_headers,
            "missing_headers": missing_headers
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

