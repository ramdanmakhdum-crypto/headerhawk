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

@app.command()
def scan(url: str):
    """Scan security headers dari URL target."""
    console.print(f"[bold blue]Scanning:[/bold blue] {url}\n")

    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        headers = response.headers

        table = Table(title=f"Security Headers Report: {url}")
        table.add_column("Headers", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Value", style="green")

        score = 0
        total_weight = sum(SECURITY_HEADERS.values())

        for header, weight in SECURITY_HEADERS.items():
            if header in headers:
                table.add_row(header, "Ada", headers[header][:50] + "...")
                score += weight
            else:
                 table.add_row(header, "Tidak Ada", "_")


        final_score = int((score / total_weight) * 100)

        console.print(table)


        if final_score >= 90:
            grade = "A"
        elif final_score >= 75:
            grade = "B"
        elif final_score >= 60:
            grade = "C"
        elif final_score >= 40:
            grade = "D"
        else:
            grade = "F"

        console.print(f"\n[bold]Skor Keamanan:[/bold] {final_score}/100 | [bold]Grade:[/bold] {grade}")

    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}")

if __name__ == "__main__":
    app()
