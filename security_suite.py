import subprocess
import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

app = typer.Typer()
console = Console()

API_URL = "https://headerhawk-r8zd.onrender.com/scan"

def scan_wifi():
    console.print("\n[bold cyan]📡 Memulai Scan Jaringan Lokal (Wi-Fi)...[/bold cyan]")
    console.print("[yellow]Mencari perangkat yang terhubung (mohon tunggu)...[/yellow]\n")
    
    try:
        # Menjalankan nmap untuk scan cepat (Ping Scan)
        # Menggunakan 'sudo' karena nmap butuh akses root untuk scan jaringan
        result = subprocess.run(["sudo", "nmap", "-sn", "192.168.1.0/24"], capture_output=True, text=True)
        
        # Parsing hasil nmap
        lines = result.stdout.split('\n')
        devices = []
        current_ip = ""
        
        for line in lines:
            if "Nmap scan report for" in line:
                current_ip = line.split("for ")[-1].strip()
            elif "MAC Address:" in line:
                mac = line.split("MAC Address: ")[-1].strip()
                devices.append((current_ip, mac))

        if not devices:
            console.print("[red]Tidak ada perangkat yang terdeteksi atau jaringan berbeda.[/red]")
            return

        table = Table(title="Perangkat di Jaringan Kamu")
        table.add_column("IP Address", style="green")
        table.add_column("MAC Address (Identitas Perangkat)", style="magenta")
        
        for dev in devices:
            table.add_row(dev[0], dev[1])
            
        console.print(table)
        console.print("\n[bold green]✅ Scan Wi-Fi Selesai![/bold green]")
        
    except FileNotFoundError:
        console.print("[red]Error: nmap belum terinstall.[/red]")
    except Exception as e:
        console.print(f"[red]Terjadi kesalahan: {e}[/red]")

def scan_web():
    url = Prompt.ask("\n[bold cyan]Masukkan URL website yang mau di-scan[/bold cyan]")
    console.print(f"\n[yellow]Menghubungi API HeaderHawk di Cloud...[/yellow]")
    
    try:
        response = httpx.get(f"{API_URL}?url={url}", timeout=60) # Timeout 60s untuk jaga-jaga Render tidur
        data = response.json()
        
        if response.status_code == 200:
            console.print("\n[bold]📊 HASIL SCAN WEB:[/bold]")
            console.print(f"URL: {data['url']}")
            console.print(f"Skor: [bold yellow]{data['score']}/100[/bold yellow] | Grade: [bold]{data['grade']}[/bold]")
            
            console.print("\n[bold green]Header yang Aman:[/bold green]")
            if data['found_headers']:
                for h in data['found_headers']:
                    console.print(f" - {h}")
            else:
                console.print(" - Tidak ada (Rentan!)")
                
            console.print("\n[bold red]Header yang Hilang:[/bold red]")
            if data['missing_headers']:
                for h in data['missing_headers']:
                    console.print(f" - {h}")
            else:
                console.print(" - Tidak ada (Sempurna!)")
                
            console.print("\n[bold yellow]Info Sistem Bocor:[/bold yellow]")
            if data.get('leaked_info'):
                for k, v in data['leaked_info'].items():
                    console.print(f" - {k}: {v}")
            else:
                console.print(" - Tidak ada kebocoran")
                
        else:
            console.print(f"[red]Gagal: {data.get('detail', 'Error tidak diketahui')}[/red]")
            
    except Exception as e:
        console.print(f"[red]Gagal terhubung ke API: {e}[/red]")

@app.command()
def start():
    console.print("[bold blue]🦅 Ramdan Security Suite v1.0 🦅[/bold blue]")
    console.print("Pilih menu:")
    console.print("1. 📡 Scan Wi-Fi Lokal (Cari perangkat tersambung)")
    console.print("2. 🌐 Scan Keamanan Website (Cloud API)")
    console.print("3. ❌ Keluar")
    
    choice = Prompt.ask("\nPilih angka", choices=["1", "2", "3"])
    
    if choice == "1":
        scan_wifi()
    elif choice == "2":
        scan_web()
    else:
        console.print("Sampai jumpa, Sang Auditor! 👋")

if __name__ == "__main__":
    app()
