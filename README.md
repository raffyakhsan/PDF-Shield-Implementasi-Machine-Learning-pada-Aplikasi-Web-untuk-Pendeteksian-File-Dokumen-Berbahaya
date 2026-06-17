# 🛡️ PDF-Shield: Hybrid AI Malware Detector

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://pdf-shield-implementasi.streamlit.app/)

Aplikasi web untuk mendeteksi file PDF berbahaya (malware) menggunakan kombinasi **model Machine Learning (Random Forest)** dan **analisis forensik heuristik**. Dibangun dengan Streamlit.

> 🚀 **Live Demo:** [https://pdf-shield-implementasi.streamlit.app/](https://pdf-shield-implementasi.streamlit.app/)

---

## 📋 Deskripsi

PDF-Shield menganalisis struktur metadata file PDF secara statis — tanpa perlu mengeksekusi file — untuk mengidentifikasi tag-tag berbahaya yang umum digunakan oleh malware PDF. Sistem ini menggabungkan dua pendekatan:

1. **Model AI (Random Forest)** — Prediksi berbasis statistik dari 33 fitur metadata PDF.
2. **Forensik Heuristik** — Analisis aturan berbasis tag berbahaya (seperti `/Launch`, `/JS`, `/OpenAction`) untuk menjelaskan hasil prediksi secara transparan.

---

## 🗂️ Struktur Proyek

```
deteksi-pdf/
├── app.py              # Aplikasi web utama (Streamlit)
├── train.py            # Script pelatihan model Random Forest
├── Final.csv           # Dataset fitur metadata PDF (Benign & Malicious)
├── otak_ai_pdf_rf.pkl  # Model Random Forest yang sudah dilatih
├── style.css           # Styling tampilan antarmuka
└── requirements.txt    # Dependensi Python
```

---

## ⚙️ Instalasi

### Prasyarat
- Python 3.8+
- pip

### Langkah Instalasi

```bash
# 1. Clone atau ekstrak repositori ini
git clone https://github.com/raffyakhsan/PDF-Shield-Implementasi-Machine-Learning-pada-Aplikasi-Web-untuk-Pendeteksian-File-Dokumen-Berbahaya.git

cd PDF-Shield-Implementasi-Machine-Learning-pada-Aplikasi-Web-untuk-Pendeteksian-File-Dokumen-Berbahaya

# 2. (Opsional) Buat virtual environment
python -m venv venv
source venv/bin/activate       # Linux/macOS
venv\Scripts\activate          # Windows

# 3. Install dependensi
pip install -r requirements.txt
```

---

## 🚀 Cara Menjalankan

### 1. Latih Model (jika belum ada `otak_ai_pdf_rf.pkl`)

Pastikan file `Final.csv` tersedia di direktori yang sama, lalu jalankan:

```bash
python train.py
```

Script akan:
- Memuat dan memvalidasi dataset `Final.csv`
- Melakukan pra-pemrosesan data (menangani NaN, encoding label)
- Melatih model Random Forest (`n_estimators=300`, `max_depth=6`, `class_weight=balanced`)
- Menampilkan laporan evaluasi (Akurasi, ROC-AUC, Confusion Matrix)
- Menyimpan model ke file `otak_ai_pdf_rf.pkl`

### 2. Jalankan Aplikasi Web

```bash
streamlit run app.py
```

Buka browser dan akses `http://localhost:8501`.

---

## 🖥️ Cara Penggunaan Aplikasi

1. **Upload File PDF** — Seret atau pilih file PDF yang ingin diperiksa.
2. **Klik "Mulai Pemindaian"** — Sistem akan mengekstrak fitur metadata dari file.
3. **Baca Hasil Analisis:**
   - **Aman** ✅ — Tidak terdeteksi pola berbahaya.
   - **Malware** ⛔ — File mengandung indikator berbahaya.
4. **Lihat Detail Forensik** — Tabel metadata PDF dan profil ancaman yang terdeteksi (jika ada).
5. **Panduan Aman** — Klik tombol ini untuk rekomendasi keamanan saat membuka PDF.

---

## 🔍 Fitur yang Dianalisis

Sistem mengekstrak **33 fitur metadata statis** dari file PDF, antara lain:

| Kategori | Tag / Fitur |
|---|---|
| **Eksekusi Berbahaya** | `/JS`, `/JavaScript`, `/Launch`, `/OpenAction`, `/AA` |
| **Konten Tertanam** | `/EmbeddedFile`, `/RichMedia`, `/XFA` |
| **Struktur PDF** | `obj`, `endobj`, `stream`, `xref`, `trailer`, `startxref` |
| **Enkripsi & Form** | `/Encrypt`, `/AcroForm`, `/SubmitForm`, `/ImportData` |
| **Referensi Eksternal** | `/URI`, `/JBIG2Decode`, `/ObjStm` |
| **Metadata Umum** | `pdf_size`, `metadata_size`, `pages`, `header` |

---

## 🧠 Logika Hybrid (Anti-Paranoid)

Untuk menghindari false positive yang berlebihan, PDF-Shield menerapkan **logika keputusan hybrid**:

- Jika ditemukan **tag fatal** (`/JS`, `/JavaScript`, `/Launch`): keputusan mengikuti model AI (threshold 50%).
- Jika **tidak ada tag fatal** dan keyakinan malware **50%–90%**: hasil dipaksa menjadi **Aman** dengan catatan transparan.
- Jika **tidak ada tag fatal** dan keyakinan malware **≥ 90%**: keputusan tetap **Malware** (anomali struktur tingkat tinggi).

---

## 🤖 Tautan Model

Model Random Forest yang sudah dilatih tersedia langsung di repositori ini:

| File | Deskripsi | Unduh |
|---|---|---|
| `otak_ai_pdf_rf.pkl` | Model Random Forest terlatih | [Download](../../raw/main/otak_ai_pdf_rf.pkl) |

> Model dapat langsung digunakan tanpa perlu melatih ulang. Letakkan file `.pkl` di direktori yang sama dengan `app.py`.

---

## 📊 Dataset

Dataset `Final.csv` berisi sampel file PDF dengan label:
- `0` = **Benign** (Aman)
- `1` = **Malicious** (Malware)

Kolom fitur utama: `pdf_size`, `metadata_size`, `pages`, `JS`, `Javascript`, `AA`, `OpenAction`, `launch`, `EmbeddedFile`, `encrypt`, `ObjStm`, dll.

> ⚠️ File `Final.csv` berisi data latih dan **tidak boleh dihapus** jika ingin melatih ulang model.

---

## 📦 Dependensi

```
streamlit
pandas
numpy
scikit-learn
joblib
```

---

## ⚠️ Disclaimer

> PDF-Shield adalah alat bantu analisis statis dan **bukan pengganti antivirus profesional**. Hasil deteksi dapat mengandung false positive maupun false negative. Selalu verifikasi file mencurigakan dengan tools keamanan tambahan atau sandbox analysis.

---

## 📄 Lisensi

Proyek ini dibuat untuk keperluan edukasi dan penelitian keamanan siber.

---

## 🌐 Deploy

Aplikasi ini di-deploy menggunakan **Streamlit Community Cloud**.

| | |
|---|---|
| **Platform** | Streamlit Community Cloud |
| **URL** | https://pdf-shield-implementasi.streamlit.app/ |
| **Branch** | `main` |
| **Entry point** | `app.py` |

Untuk deploy ulang atau fork ke akun sendiri:
1. Fork repositori ini
2. Login ke [share.streamlit.io](https://share.streamlit.io)
3. Pilih repo → set **Main file path** ke `app.py`
4. Klik **Deploy**
