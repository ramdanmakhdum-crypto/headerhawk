import ipaddress
import json
import socket
from urllib.parse import urlparse

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer()
console = Console()

SECURITY_HEADERS = {
    "strict-transport-security": 20,
    "content-security-policy": 20,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 15,
    "permissions-policy": 15,
}
LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator"]
GRADES = [(90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F")]
MAX_REDIRECTS = 5


class UnsafeURL(ValueError):
    """URL ditolak: skema salah atau mengarah ke jaringan internal."""


def normalize_url(url: str) -> str:
    url = url.strip()
    return url if "://" in url else "https://" + url


def ensure_public(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise UnsafeURL("Hanya http/https yang diizinkan")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror:
        raise UnsafeURL("Domain tidak ditemukan")
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise UnsafeURL("Alamat internal/privat tidak diizinkan")


def fetch_headers(url: str):
    """Setiap redirect divalidasi ulang sebelum diikuti."""
    with httpx.Client(timeout=10, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            ensure_public(url)
            resp = client.get(url)
            if resp.is_redirect and "location" in resp.headers:
                url = str(resp.url.join(resp.headers["location"]))
                continue
            return resp.headers, str(resp.url)
    raise UnsafeURL("Terlalu banyak redirect")


def analyze(url: str) -> dict:
    headers, final_url = fetch_headers(normalize_url(url))
    found, missing, score = {}, [], 0
    total = sum(SECURITY_HEADERS.values())
    for name, weight in SECURITY_HEADERS.items():
        if name in headers:
            found[name] = headers[name]
            score += weight
        else:
            missing.append(name)
    final = int(score / total * 100)
    grade = next(g for limit, g in GRADES if final >= limit)
    return {"url": final_url, "score": final, "grade": grade,
            "found": found, "missing": missing,
            "leaked_info": {h: headers[h] for h in LEAK_HEADERS if h in headers}}


@app.command()
def scan(url: str, as_json: bool = typer.Option(False, "--json", help="Output JSON")):
    """Scan security headers dari URL target."""
    try:
        result = analyze(url)
    except (UnsafeURL, httpx.HTTPError) as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)

    if as_json:
        print(json.dumps(result, indent=2))
        return

    table = Table(title=f"Security Headers Report: {result['url']}")
    table.add_column("Header", style="cyan")
    table.add_column("Status", style="magenta")
    table.add_column("Value", style="green")
    for name in SECURITY_HEADERS:
        if name in result["found"]:
            v = result["found"][name]
            table.add_row(name, "Ada", v if len(v) <= 50 else v[:50] + "...")
        else:
            table.add_row(name, "Tidak Ada", "-")
    console.print(table)
    console.print(f"\n[bold]Skor:[/bold] {result['score']}/100 | "
                  f"[bold]Grade:[/bold] {result['grade']}")


if __name__ == "__main__":
    app()
