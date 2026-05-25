"""
========================================================
  PDF-Shield: Hybrid AI Malware Detector
  FASE 2, 3 & 4 - Aplikasi Web Streamlit (app.py)

  Deskripsi:
    Antarmuka web untuk menganalisis file PDF menggunakan
    model Random Forest + Forensik Heuristik Hybrid.

  Cara menjalankan:
    streamlit run app.py

  Catatan:
    Tampilan (CSS) dikelola terpisah di file style.css
========================================================
"""

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import re
import json
import os
from datetime import datetime

# ─────────────────────────────────────────────
#  KONFIGURASI HALAMAN STREAMLIT
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="PDF-Shield | Detektor Virus AI",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────
#  MUAT CSS DARI FILE EKSTERNAL
#  Semua gaya tampilan dikelola di style.css
# ─────────────────────────────────────────────
with open("style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  KONFIGURASI GLOBAL APLIKASI
# ─────────────────────────────────────────────
MODEL_PATH = "otak_ai_pdf_rf.pkl"

# Daftar tag metadata berbahaya yang diekstrak dari PDF
# Setiap entry: (nama_tag, regex_pattern, deskripsi)
DEFINISI_FITUR_BERBAHAYA = [
    ("/JS",            r"/JS",            "Kode JavaScript Inline"),
    ("/JavaScript",    r"/JavaScript",    "Referensi Aksi JavaScript"),
    ("/OpenAction",    r"/OpenAction",    "Aksi Otomatis Saat Dibuka"),
    ("/AA",            r"/AA",            "Aksi Tambahan Otomatis"),
    ("/RichMedia",     r"/RichMedia",     "Konten Media Kaya (Flash)"),
    ("/Launch",        r"/Launch",        "Eksekusi Program Eksternal"),
    ("/EmbeddedFile",  r"/EmbeddedFile",  "File Tertanam di Dalam PDF"),
    ("/XFA",           r"/XFA",           "XML Form Architecture"),
    ("/Colors",        r"/Colors",        "Override Ruang Warna"),
    ("/AcroForm",      r"/AcroForm",      "Adobe Acrobat Form"),
    ("/URI",           r"/URI",           "Referensi URI Eksternal"),
    ("/SubmitForm",    r"/SubmitForm",    "Pengiriman Data Form"),
    ("/ImportData",    r"/ImportData",    "Impor Data Eksternal"),
    ("/JBIG2Decode",   r"/JBIG2Decode",   "Filter Kompresi JBIG2"),
    ("/ObjStm",        r"/ObjStm",        "Aliran Objek Terkompresi"),
    ("/Encrypt",       r"/Encrypt",       "Enkripsi Dokumen"),
    ("/Annot",         r"/Annot",         "Anotasi Dokumen"),
    ("/Page",          r"/Page[^s]",      "Referensi Halaman"),
    ("header",         r"%PDF-",          "Header PDF Standar"),
    ("obj",            r"\b\d+ \d+ obj\b","Jumlah Objek PDF"),
    ("endobj",         r"endobj",         "Penutup Objek PDF"),
    ("stream",         r"\bstream\b",     "Aliran Data"),
    ("endstream",      r"endstream",      "Penutup Aliran Data"),
    ("xref",           r"\bxref\b",       "Tabel Referensi Silang"),
    ("trailer",        r"\btrailer\b",    "Trailer Dokumen"),
    ("startxref",      r"startxref",      "Penanda Awal Xref"),
]


# ─────────────────────────────────────────────
#  FUNGSI: Muat Model (dengan Cache)
# ─────────────────────────────────────────────
@st.cache_resource(show_spinner=False)
def muat_model(path: str):
    """
    Memuat artefak model dari file .pkl menggunakan joblib.
    Hasil di-cache agar tidak dimuat ulang setiap request.

    Returns:
        Tuple (model, feature_names) atau (None, None) jika gagal.
    """
    if not os.path.exists(path):
        return None, None

    try:
        artefak = joblib.load(path)
        # Mendukung dua format: dictionary (dari train.py baru) atau model langsung
        if isinstance(artefak, dict):
            return artefak["model"], artefak.get("feature_names", [])
        else:
            return artefak, []
    except Exception as e:
        st.error(f"Gagal memuat model: {e}")
        return None, None


# ─────────────────────────────────────────────
#  FUNGSI: Ekstraksi Fitur dari Byte PDF
# ─────────────────────────────────────────────
def ekstrak_fitur_pdf(file_bytes: bytes) -> dict:
    """
    Membaca byte mentah file PDF dan menghitung kemunculan
    setiap tag metadata menggunakan regex.

    Args:
        file_bytes: Konten biner file PDF.

    Returns:
        Dictionary berisi nama fitur -> jumlah kemunculan.
    """
    # Dekode byte menggunakan latin-1 agar karakter biner tidak menyebabkan error
    konten_teks = file_bytes.decode("latin-1", errors="ignore")

    hasil_ekstraksi = {}
    for nama_tag, pola_regex, _ in DEFINISI_FITUR_BERBAHAYA:
        temuan = re.findall(pola_regex, konten_teks, re.IGNORECASE)
        hasil_ekstraksi[nama_tag] = len(temuan)

    # Tambahan fitur turunan yang sering digunakan dalam dataset PDF
    hasil_ekstraksi["pdfid_version"]   = 1 if re.search(r"%PDF-\d+\.\d+", konten_teks) else 0
    hasil_ekstraksi["count_obj"]       = hasil_ekstraksi.get("obj", 0)
    hasil_ekstraksi["count_endobj"]    = hasil_ekstraksi.get("endobj", 0)
    hasil_ekstraksi["count_stream"]    = hasil_ekstraksi.get("stream", 0)
    hasil_ekstraksi["count_endstream"] = hasil_ekstraksi.get("endstream", 0)
    hasil_ekstraksi["count_xref"]      = hasil_ekstraksi.get("xref", 0)
    hasil_ekstraksi["count_trailer"]   = hasil_ekstraksi.get("trailer", 0)
    hasil_ekstraksi["count_startxref"] = hasil_ekstraksi.get("startxref", 0)
    hasil_ekstraksi["count_page"]      = hasil_ekstraksi.get("/Page", 0)
    hasil_ekstraksi["count_encrypt"]   = hasil_ekstraksi.get("/Encrypt", 0)

    return hasil_ekstraksi


# ─────────────────────────────────────────────
#  FUNGSI: Selaraskan Fitur dengan Skema Training
# ─────────────────────────────────────────────
def selaraskan_fitur(fitur_dict: dict, feature_names_training: list) -> pd.DataFrame:
    """
    Mengonversi dictionary fitur menjadi DataFrame dengan kolom
    yang persis sama seperti data training model.
    Kolom yang tidak ada diisi 0, kolom ekstra dihapus.

    Args:
        fitur_dict: Dictionary fitur hasil ekstraksi.
        feature_names_training: Daftar nama kolom dari training.

    Returns:
        DataFrame satu baris dengan kolom sesuai training.
    """
    df_fitur = pd.DataFrame([fitur_dict])

    if feature_names_training:
        # Tambahkan kolom yang hilang dengan nilai 0
        for kolom in feature_names_training:
            if kolom not in df_fitur.columns:
                df_fitur[kolom] = 0
        # Urutkan kolom sesuai urutan training, buang kolom ekstra
        df_fitur = df_fitur[feature_names_training]

    return df_fitur


# ─────────────────────────────────────────────
#  FUNGSI: Analisis Forensik Heuristik
# ─────────────────────────────────────────────
def analisis_forensik_heuristik(fitur_dict: dict) -> list:
    """
    Melakukan profiling ancaman berdasarkan tag metadata berbahaya.
    Fungsi ini HANYA menjelaskan prediksi AI, TIDAK mengubahnya.

    Args:
        fitur_dict: Dictionary fitur hasil ekstraksi.

    Returns:
        List of dict berisi profil ancaman yang terdeteksi.
    """
    profil_ancaman = []

    # ── Aturan Heuristik: Urutan Prioritas Berdasarkan Tingkat Keparahan ──

    # [1] KRITIS - Command Execution via /Launch
    if fitur_dict.get("/Launch", 0) > 0:
        profil_ancaman.append({
            "tipe":      "Eksekusi Perintah (Command Execution)",
            "level":     "KRITIS",
            "indikator": f"/Launch terdeteksi [{fitur_dict['/Launch']}x]",
            "deskripsi": (
                "Tag /Launch memungkinkan PDF untuk menjalankan program atau skrip "
                "sistem secara langsung saat dokumen dibuka. Ini adalah vektor eksploitasi "
                "paling berbahaya yang sering digunakan oleh malware tingkat lanjut (APT)."
            ),
            "rekomendasi": "JANGAN buka file ini. Karantina dan laporkan segera ke tim keamanan.",
        })

    # [2] TINGGI - JavaScript Injection via /JS atau /JavaScript
    if fitur_dict.get("/JS", 0) > 0 or fitur_dict.get("/JavaScript", 0) > 0:
        total_js = fitur_dict.get("/JS", 0) + fitur_dict.get("/JavaScript", 0)
        profil_ancaman.append({
            "tipe":      "Injeksi JavaScript (JavaScript Injection)",
            "level":     "TINGGI",
            "indikator": f"/JS [{fitur_dict.get('/JS',0)}x] + /JavaScript [{fitur_dict.get('/JavaScript',0)}x] = {total_js} total",
            "deskripsi": (
                "File PDF mengandung kode JavaScript tersembunyi yang dapat dieksekusi "
                "secara otomatis oleh pembaca PDF. Teknik ini digunakan untuk eksploitasi "
                "heap spray, buffer overflow, dan pengunduhan payload berbahaya."
            ),
            "rekomendasi": "Nonaktifkan JavaScript di pengaturan pembaca PDF Anda. Jangan buka file ini.",
        })

    # [3] MENENGAH - Auto-Trigger Exploit via /OpenAction
    if fitur_dict.get("/OpenAction", 0) > 0:
        profil_ancaman.append({
            "tipe":      "Eksploitasi Otomatis (Auto-Trigger Exploit)",
            "level":     "MENENGAH",
            "indikator": f"/OpenAction terdeteksi [{fitur_dict['/OpenAction']}x]",
            "deskripsi": (
                "Tag /OpenAction mengeksekusi aksi tertentu secara otomatis "
                "ketika dokumen dibuka, tanpa memerlukan interaksi pengguna. "
                "Sering dikombinasikan dengan JavaScript untuk serangan drive-by."
            ),
            "rekomendasi": "Verifikasi sumber file sebelum membukanya. Gunakan lingkungan sandbox.",
        })

    # [3b] MENENGAH - Additional Action /AA
    if fitur_dict.get("/AA", 0) > 0:
        profil_ancaman.append({
            "tipe":      "Aksi Otomatis Tambahan (/AA)",
            "level":     "MENENGAH",
            "indikator": f"/AA terdeteksi [{fitur_dict['/AA']}x]",
            "deskripsi": (
                "Additional Actions (/AA) memungkinkan eksekusi aksi pada event tertentu "
                "(scroll, focus, blur). Dapat digunakan untuk memicu payload secara bertahap."
            ),
            "rekomendasi": "Analisis lebih lanjut diperlukan. Gunakan sandbox analysis.",
        })

    # [3c] MENENGAH - Embedded File
    if fitur_dict.get("/EmbeddedFile", 0) > 0:
        profil_ancaman.append({
            "tipe":      "File Tertanam Mencurigakan (/EmbeddedFile)",
            "level":     "MENENGAH",
            "indikator": f"/EmbeddedFile terdeteksi [{fitur_dict['/EmbeddedFile']}x]",
            "deskripsi": (
                "PDF mengandung file yang disembunyikan di dalamnya. File tertanam "
                "dapat berupa executable, script, atau dokumen berbahaya lainnya "
                "yang dirancang untuk di-drop ke sistem target."
            ),
            "rekomendasi": "Ekstrak dan analisis file tertanam menggunakan tools forensik.",
        })

    # [4] ANOMALI - Tidak ada indikator eksplisit tapi AI mendeteksi malware
    if not profil_ancaman:
        profil_ancaman.append({
            "tipe":      "Anomali Struktur (Unknown Structural Anomaly)",
            "level":     "RENDAH-SEDANG",
            "indikator": "Tidak ada tag berbahaya eksplisit yang terdeteksi",
            "deskripsi": (
                "Model AI mendeteksi pola statistik yang menyimpang dari dokumen PDF normal. "
                "Kemungkinan menggunakan teknik obfuskasi lanjutan, encoding khusus, atau "
                "eksploitasi berbasis struktur yang tidak terlihat oleh analisis berbasis tanda tangan. "
                "Ini adalah karakteristik malware generasi baru atau dokumen yang sangat diobfuskasi."
            ),
            "rekomendasi": "Analisis mendalam diperlukan. Kirim ke sandbox analysis dan threat intelligence platform.",
        })

    return profil_ancaman


# ─────────────────────────────────────────────
#  FUNGSI: Render Badge Level HTML
# ─────────────────────────────────────────────
def render_badge_level(level: str) -> str:
    """Menghasilkan HTML badge sesuai level ancaman."""
    kelas_map = {
        "KRITIS":        "badge-kritis",
        "TINGGI":        "badge-tinggi",
        "MENENGAH":      "badge-menengah",
        "RENDAH-SEDANG": "badge-rendah",
    }
    kelas = kelas_map.get(level.upper(), "badge-rendah")
    return f'<span class="{kelas}">● {level}</span>'


# ─────────────────────────────────────────────
#  FUNGSI: Render Tabel Detail Pemindaian
# ─────────────────────────────────────────────
def tampilkan_tabel_fitur(fitur_dict: dict):
    """Merender tabel HTML fitur metadata yang diekstrak."""
    TAG_BERBAHAYA = {
        "/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch",
        "/EmbeddedFile", "/XFA", "/RichMedia", "/URI", "/SubmitForm",
        "/ImportData", "/JBIG2Decode", "/Encrypt",
    }

    baris = ""
    for nama_tag, _, deskripsi in DEFINISI_FITUR_BERBAHAYA:
        nilai     = fitur_dict.get(nama_tag, 0)
        berbahaya = nama_tag in TAG_BERBAHAYA and nilai > 0
        kelas_td  = "danger" if berbahaya else ("ok" if nilai > 0 else "")
        ikon      = "🔴" if berbahaya else ("🟢" if nilai > 0 else "⚪")
        baris += f"""
        <tr>
            <td><span class="tag-pill">{nama_tag}</span></td>
            <td style="color:#667085;">{deskripsi}</td>
            <td class="{kelas_td}" style="text-align:center;">{ikon} {nilai}</td>
        </tr>"""

    html = f"""
    <table class="meta-table">
        <thead>
            <tr>
                <th>Tag PDF</th>
                <th>Keterangan</th>
                <th style="text-align:center;">Jumlah</th>
            </tr>
        </thead>
        <tbody>{baris}</tbody>
    </table>"""
    st.markdown(html, unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  PROGRAM UTAMA
# ─────────────────────────────────────────────
def main():

    # ══════════════════════════════════════
    #  HEADER — Judul besar, tagline simpel
    # ══════════════════════════════════════
    st.markdown("""
    <div class="app-header">
        <h1>PDF-<em>Shield</em></h1>
        <p class="tagline">
            Pilih file PDF Anda, dan sistem akan memindai struktur file
            untuk mendeteksi potensi virus.
        </p>
    </div>
    <hr class="header-rule">
    """, unsafe_allow_html=True)

    # ══════════════════════════════════════
    #  MUAT MODEL
    # ══════════════════════════════════════
    with st.spinner("Memuat model..."):
        model, feature_names = muat_model(MODEL_PATH)

    # Banner jika model belum tersedia
    if model is None:
        st.markdown("""
        <div class="missing-banner">
            <div class="mb-title">⚠ Model Belum Siap</div>
            <p>
                File <code>otak_ai_pdf_xgb.pkl</code> tidak ditemukan.
                Jalankan perintah berikut untuk melatih model terlebih dahulu,
                dan pastikan file <code>Final.csv</code> tersedia di folder yang sama.
            </p>
        </div>
        """, unsafe_allow_html=True)
        st.code("python train.py", language="bash")
        _render_disclaimer()
        return

    # Badge status model aktif
    st.markdown("""
    <div class="model-status">
        <span class="dot"></span>
        Sistem siap — unggah file PDF untuk memulai pemindaian
    </div>
    """, unsafe_allow_html=True)

    # ══════════════════════════════════════
    #  ZONA UPLOAD
    # ══════════════════════════════════════

    file_unggah = st.file_uploader(
        label="Pilih file PDF",
        type=["pdf"],
        accept_multiple_files=False,
        help="Hanya file berformat PDF yang diterima.",
        label_visibility="collapsed",
    )

    # ══════════════════════════════════════
    #  PROSES ANALISIS
    # ══════════════════════════════════════
    if file_unggah is not None:
        # Sembunyikan seluruh area upload setelah file dipilih — diganti panel custom di bawah
        st.markdown(
            "<style>"
            "[data-testid=\"stFileUploaderFile\"]{display:none!important;}"
            "[data-testid=\"stFileUploaderDropzone\"]::before{display:none!important;}"
            "[data-testid=\"stFileUploaderDropzone\"]{display:none!important;}"
            "[data-testid=\"stFileUploader\"] section{display:none!important;}"
            "[data-testid=\"stFileUploader\"]{"
            "border:none!important;background:transparent!important;"
            "padding:0!important;min-height:0!important;margin:0!important;}"
            "</style>",
            unsafe_allow_html=True,
        )

        # ── Panel Premium: Info file + action panel ──
        ukuran_kb  = file_unggah.size / 1024
        ukuran_mb  = ukuran_kb / 1024
        ukuran_str = f"{ukuran_mb:.2f} MB" if ukuran_mb >= 1 else f"{ukuran_kb:.1f} KB"

        srp_html = (
            '<div class="scan-ready-panel">' +
            '<div class="srp-file-info">' +
            '<div class="srp-file-icon-wrap">' +
            '<svg width="28" height="28" viewBox="0 0 24 24" fill="none">' +
            '<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke="#009688" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
            '<polyline points="14,2 14,8 20,8" stroke="#009688" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>' +
            '<line x1="16" y1="13" x2="8" y2="13" stroke="#009688" stroke-width="1.6" stroke-linecap="round"/>' +
            '<line x1="16" y1="17" x2="8" y2="17" stroke="#009688" stroke-width="1.6" stroke-linecap="round"/>' +
            '</svg></div>' +
            '<div class="srp-file-details">' +
            f'<div class="srp-file-name">{file_unggah.name}</div>' +
            '<div class="srp-file-meta">' +
            '<span class="srp-meta-badge">PDF</span>' +
            f'<span>{ukuran_str}</span>' +
            '<span class="srp-dot-sep">&nbsp;&middot;&nbsp;</span>' +
            '<span class="srp-ready-text">&#10003; Siap dipindai</span>' +
            '</div></div></div>' +
            '<div class="srp-checklist">' +
            '<div class="srp-check-item srp-check-ok"><span class="srp-chk">&#10003;</span> File terdeteksi</div>' +
            '<div class="srp-check-item srp-check-ok"><span class="srp-chk">&#10003;</span> Format valid (PDF)</div>' +
            '<div class="srp-check-item srp-check-ok"><span class="srp-chk">&#10003;</span> Model AI aktif</div>' +
            '<div class="srp-check-item srp-check-pending"><span class="srp-chk-p">&#9678;</span> Analisis forensik</div>' +
            '</div></div>'
        )
        st.markdown(srp_html, unsafe_allow_html=True)

        st.markdown("<div style='height:0.5rem;'></div>", unsafe_allow_html=True)

        # ── Baris tombol: Mulai Pemindaian + Panduan Aman ──
        st.markdown("""
        <style>
        /* Desktop: tombol ikut konten */
        @media (min-width: 481px) {
            div[data-testid="column"] .stButton > button {
                width: auto !important;
                display: inline-flex !important;
            }
            div[data-testid="stHorizontalBlock"] {
                gap: 0 !important;
            }
            div[data-testid="stHorizontalBlock"] > div:nth-child(2) {
                padding-left: 1.5rem !important;
            }
        }
        /* Mobile: tombol full width, stack vertikal */
        @media (max-width: 480px) {
            div[data-testid="stHorizontalBlock"]:has(.stButton) {
                flex-direction: column !important;
                gap: 0.5rem !important;
            }
            div[data-testid="stHorizontalBlock"]:has(.stButton) > div {
                width: 100% !important;
                flex: unset !important;
                min-width: unset !important;
            }
            div[data-testid="column"] .stButton > button {
                width: 100% !important;
                display: flex !important;
                justify-content: center !important;
            }
        }
        </style>
        """, unsafe_allow_html=True)
        col_btn_main, col_btn_guide, _ = st.columns([3.2, 2.4, 9.4])
        with col_btn_main:
            tombol_analisis = st.button(
                "Mulai Pemindaian",
                use_container_width=True,
                type="primary",
                key="btn_scan",
            )
        with col_btn_guide:
            tombol_info = st.button(
                "Panduan Aman",
                use_container_width=True,
                type="secondary",
                key="btn_guide",
            )

        # ── Panel panduan: muncul jika tombol ditekan ──
        if tombol_info:
            st.markdown("""
            <div class="guide-panel">
                <div class="gp-title">&#128203; Panduan Keamanan PDF</div>
                <div class="gp-grid">
                    <div class="gp-item">
                        <span class="gp-icon">&#128269;</span>
                        <div>
                            <strong>Periksa Sumber File</strong>
                            <p>Jangan buka PDF dari email tidak dikenal, link mencurigakan, atau kiriman tak terduga meski terlihat resmi.</p>
                        </div>
                    </div>
                    <div class="gp-item">
                        <span class="gp-icon">&#9881;&#65039;</span>
                        <div>
                            <strong>Nonaktifkan JavaScript di PDF Reader</strong>
                            <p>Sebagian besar PDF reader (Foxit, SumatraPDF, browser bawaan) memiliki opsi menonaktifkan eksekusi JavaScript di pengaturan keamanan.</p>
                        </div>
                    </div>
                    <div class="gp-item">
                        <span class="gp-icon">&#127760;</span>
                        <div>
                            <strong>Buka via Browser atau Viewer Online</strong>
                            <p>Gunakan Google Chrome, Firefox, atau Google Drive untuk membuka PDF — lebih aman karena JavaScript PDF diblokir secara default.</p>
                        </div>
                    </div>
                    <div class="gp-item">
                        <span class="gp-icon">&#128465;&#65039;</span>
                        <div>
                            <strong>Karantina &amp; Laporkan</strong>
                            <p>Jika terdeteksi berbahaya, jangan buka, jangan teruskan. Pindahkan ke folder karantina dan laporkan ke tim IT atau hapus permanen.</p>
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        if tombol_analisis:
            with st.spinner("Memindai file PDF..."):

                # ── Langkah 1: Baca byte ──
                byte_file = file_unggah.read()

                # ── Langkah 2: Ekstraksi fitur ──
                fitur_dict = ekstrak_fitur_pdf(byte_file)

                # --- TRANSLATOR WEB -> AI ---
                # Mengubah format web ("/AA") jadi format CSV ("AA")
                fitur_untuk_ai = {
                    "JS":            fitur_dict.get("/JS", 0),
                    "Javascript":    fitur_dict.get("/JavaScript", 0),
                    "AA":            fitur_dict.get("/AA", 0),
                    "OpenAction":    fitur_dict.get("/OpenAction", 0),
                    "Acroform":      fitur_dict.get("/AcroForm", 0),
                    "JBIG2Decode":   fitur_dict.get("/JBIG2Decode", 0),
                    "RichMedia":     fitur_dict.get("/RichMedia", 0),
                    "launch":        fitur_dict.get("/Launch", 0),
                    "EmbeddedFile":  fitur_dict.get("/EmbeddedFile", 0),
                    "XFA":           fitur_dict.get("/XFA", 0),
                    "URI":           fitur_dict.get("/URI", 0),
                    "Colors":        fitur_dict.get("/Colors", 0),
                    "ObjStm":        fitur_dict.get("/ObjStm", 0),
                    "encrypt":       fitur_dict.get("/Encrypt", 0),
                    "pages":         fitur_dict.get("/Page", 1),
                    "obj":           fitur_dict.get("obj", 0),
                    "endobj":        fitur_dict.get("endobj", 0),
                    "stream":        fitur_dict.get("stream", 0),
                    "endstream":     fitur_dict.get("endstream", 0),
                    "xref":          fitur_dict.get("xref", 0),
                    "trailer":       fitur_dict.get("trailer", 0),
                    "startxref":     fitur_dict.get("startxref", 0),
                    "pdf_size":      350.0,
                    "metadata_size": 180.0,
                }

                # ── Langkah 3: Selaraskan fitur ──
                df_fitur = selaraskan_fitur(fitur_untuk_ai, feature_names)

                # ── Langkah 4: Prediksi Random Forest & HYBRID OVERRIDE ──
                probabilitas      = model.predict_proba(df_fitur)[0]
                keyakinan_malware = probabilitas[1] * 100   # backend only
                keyakinan_aman    = probabilitas[0] * 100   # backend only

                # Cek apakah ada tag yang BENAR-BENAR fatal (Script/Command)
                ada_tag_fatal = (
                    fitur_dict.get("/JS", 0) > 0 or
                    fitur_dict.get("/JavaScript", 0) > 0 or
                    fitur_dict.get("/Launch", 0) > 0
                )

                # Flag Transparansi (Biar ga nipu user!)
                intervensi_heuristik = False

                # LOGIKA HYBRID (Tuning Anti-Paranoid)
                if ada_tag_fatal:
                    # Jika ada indikasi fatal, batas toleransi normal 50%
                    prediksi = 1 if keyakinan_malware >= 50.0 else 0
                else:
                    # Jika ga ada tag fatal, tapi AI curiga (50% - 90%)
                    if 50.0 <= keyakinan_malware < 90.0:
                        prediksi = 0              # Paksa jadi Aman
                        intervensi_heuristik = True  # Nyalakan alarm transparan
                    else:
                        prediksi = 1 if keyakinan_malware >= 90.0 else 0

                # ── Langkah 5: Analisis Forensik Heuristik (jika terdeteksi) ──
                profil_ancaman = []
                if prediksi == 1:
                    profil_ancaman = analisis_forensik_heuristik(fitur_dict)

            # ══════════════════════════════════════
            #  TAMPILKAN HASIL
            # ══════════════════════════════════════
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("""<div class="sec-label">Hasil Pemindaian</div>""",
                        unsafe_allow_html=True)

            if prediksi == 0:
                # ── Peringatan Hybrid Override (tanpa angka persentase) ──
                if intervensi_heuristik:
                    st.warning(
                        "🛡️ **Catatan Sistem:** AI mendeteksi sedikit ketidakwajaran pada struktur "
                        "file ini. Namun, karena tidak ada perintah berbahaya yang nyata "
                        "(seperti skrip atau eksekutor) yang ditemukan, file ini dianggap **aman**."
                    )

                # ── Kotak hasil: AMAN ──
                st.markdown(f"""
                <div class="result-safe">
                    <span class="rs-icon"></span>
                    <div class="rs-title">File Aman</div>
                    <p class="rs-desc">
                        File <strong>{file_unggah.name}</strong> tidak menunjukkan tanda-tanda
                        berbahaya. Tidak ada indikasi virus yang terdeteksi dalam struktur file ini.
                    </p>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)
                ca, cb, cc = st.columns(3)
                with ca: st.metric("Status",        "AMAN",  delta="Tidak Terancam")
                with cb: st.metric("Hasil AI",      "Aman")
                with cc: st.metric("Sinyal Bahaya", "0")

                st.success(
                    f"✔ File **{file_unggah.name}** lolos pemindaian. "
                    "Tidak ada ancaman yang ditemukan."
                )

            else:
                # ── Kotak hasil: VIRUS (UI pakai "Virus", log JSON tetap "MALWARE") ──
                st.markdown(f"""
                <div class="result-virus">
                    <span class="rm-icon"></span>
                    <div class="rm-title">Potensi Virus Terdeteksi</div>
                    <p class="rm-desc">
                        File <strong>{file_unggah.name}</strong> terindikasi mengandung
                        konten berbahaya. Sebaiknya <strong>jangan dibuka</strong> dan
                        hindari meneruskan file ini ke orang lain.
                    </p>
                </div>
                """, unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)
                ca, cb, cc = st.columns(3)
                with ca: st.metric("Status",         "BERBAHAYA", delta="Virus", delta_color="inverse")
                with cb: st.metric("Hasil AI",       "Berbahaya")
                with cc: st.metric("Sinyal Bahaya",  str(len(profil_ancaman)))

                st.error(
                    f"File **{file_unggah.name}** terindikasi mengandung virus. "
                    "Jangan buka dan segera hapus atau karantina file ini!"
                )

                # ── Detail Temuan ──
                st.markdown("<br>", unsafe_allow_html=True)
                st.markdown("""<div class="sec-label">Detail Temuan</div>""",
                            unsafe_allow_html=True)
                st.markdown(
                    "<p style='font-size:0.9rem;color:#667085;margin:-0.25rem 0 0.5rem;'>"
                    "Berikut adalah temuan-temuan yang menjadi dasar penilaian sistem. "
                    "<strong style='color:#92400e;'>Catatan:</strong> Daftar ini bersifat "
                    "penjelasan tambahan dan tidak mengubah hasil pemindaian di atas."
                    "</p>",
                    unsafe_allow_html=True,
                )

                for i, ancaman in enumerate(profil_ancaman, 1):
                    badge = render_badge_level(ancaman["level"])
                    st.markdown(f"""
                    <div class="threat-card">
                        <div class="tc-header">
                            <span class="tc-num">#{i:02d}</span>
                            <span class="tc-title">{ancaman["tipe"]}</span>
                            {badge}
                        </div>
                        <div>
                            <span class="tc-indicator">📍 {ancaman["indikator"]}</span>
                        </div>
                        <p class="tc-desc">{ancaman["deskripsi"]}</p>
                        <div class="tc-rec">
                            <span>💡</span>
                            <span><strong>Saran:</strong> {ancaman["rekomendasi"]}</span>
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

            # ══════════════════════════════════════
            #  TABEL DATA STRUKTUR FILE (selalu tampil)
            # ══════════════════════════════════════
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("""<div class="sec-label">Data Struktur File</div>""",
                        unsafe_allow_html=True)
            tampilkan_tabel_fitur(fitur_dict)

            # ══════════════════════════════════════
            #  EXPANDER LOG JSON
            #  Angka persentase keyakinan AI HANYA ada di sini
            # ══════════════════════════════════════
            st.markdown("<br>", unsafe_allow_html=True)

            # Label di log JSON tetap "MALWARE" (bukan "VIRUS") untuk keperluan audit
            log_json = {
                "metadata_laporan": {
                    "nama_file":      file_unggah.name,
                    "ukuran_bytes":   file_unggah.size,
                    "waktu_analisis": datetime.now().isoformat(),
                    "versi_sistem":   "PDF-Shield v1.0.0",
                },
                "hasil_prediksi_ai": {
                    "label":                 "MALWARE" if prediksi == 1 else "AMAN",
                    "kode_prediksi":         int(prediksi),
                    "keyakinan_aman_pct":    float(round(keyakinan_aman, 4)),
                    "keyakinan_malware_pct": float(round(keyakinan_malware, 4)),
                    "algoritma":             "Random Forest (RandomForestClassifier)",
                    "intervensi_heuristik":  intervensi_heuristik,
                },
                "hasil_forensik_heuristik": profil_ancaman if prediksi == 1 else [],
                "fitur_metadata_ekstraksi": fitur_dict,
                "skema_fitur_training": {
                    "jumlah_fitur": len(feature_names),
                    "nama_fitur":   feature_names,
                },
            }

            with st.expander("📋 Log Teknis — Data Lengkap Pemindaian", expanded=False):
                st.markdown(
                    "<p style='font-size:0.87rem;color:#667085;margin-bottom:0.75rem;'>"
                    "Data mentah lengkap dari proses pemindaian, termasuk skor keyakinan AI. "
                    "Berguna untuk keperluan audit atau analisis lanjutan."
                    "</p>",
                    unsafe_allow_html=True,
                )
                st.json(log_json, expanded=True)

                json_str      = json.dumps(log_json, indent=2, ensure_ascii=False)
                nama_file_log = (
                    f"pdfshield_log_{file_unggah.name}_"
                    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                )
                st.download_button(
                    label="Unduh Log",
                    data=json_str.encode("utf-8"),
                    file_name=nama_file_log,
                    mime="application/json",
                    use_container_width=False,
                )

    # ══════════════════════════════════════
    #  DISCLAIMER
    # ══════════════════════════════════════
    _render_disclaimer()


def _render_disclaimer():
    """Disclaimer ringkas dan natural di bagian bawah halaman."""
    st.markdown("""
    <div class="disclaimer-strip">
        ⚠️ <strong>Catatan:</strong> Hasil pemindaian ini adalah indikasi awal berbasis
        Machine Learning. Pastikan untuk tetap berhati-hati saat membuka dokumen
        dari sumber yang tidak dikenal.
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────
if __name__ == "__main__":
    main()
