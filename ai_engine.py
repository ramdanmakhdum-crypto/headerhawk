import os
from dotenv import load_dotenv
load_dotenv()
import google.generativeai as genai

def analyze_with_ai(scan_data):
    # Ambil API Key dari environment variable
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "Error: API Key AI belum dipasang."

    genai.configure(api_key=api_key)
    # Gunakan model Gemini 1.5 Flash (cepat dan gratis)
    model = genai.GenerativeModel('gemini-1.5-flash')

    prompt = f"""
    Kamu adalah seorang ahli keamanan siber (Cybersecurity Expert).
    Saya baru saja melakukan scan keamanan pada website: {scan_data['url']}
    
    Hasil scan:
    - Skor Keamanan: {scan_data['score']}/100 (Grade: {scan_data['grade']})
    - Header yang Hilang: {', '.join(scan_data['missing_headers']) if scan_data['missing_headers'] else 'Tidak ada'}
    - Informasi Sistem Bocor: {scan_data['leaked_info']}
    
    Tolong berikan analisis singkat (maksimal 3 paragraf) dalam bahasa Indonesia yang mudah dimengerti.
    Jelaskan risiko dari header yang hilang, dan berikan 1-2 saran perbaikan untuk pemilik website tersebut.
    """

    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Gagal menghubungi AI: {str(e)}"
