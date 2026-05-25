"""
========================================================
  PDF-Shield: Hybrid AI Malware Detector
  FASE 1 - Pelatihan Model (train.py)
  
  Deskripsi:
    Script ini digunakan untuk melatih model XGBoost
    menggunakan dataset 'Final.csv' yang berisi fitur
    metadata statis dari file PDF.
  
  Output:
    - otak_ai_pdf_xgb.pkl  : Model XGBoost terlatih
========================================================
"""

import pandas as pd
import numpy as np
import joblib
import os
import warnings
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
    roc_auc_score,
)
from sklearn.preprocessing import LabelEncoder

warnings.filterwarnings("ignore")


# ─────────────────────────────────────────────
#  KONFIGURASI GLOBAL
# ─────────────────────────────────────────────
DATASET_PATH   = "Final.csv"          # Path ke file dataset
TARGET_COLUMN  = "class"              # Nama kolom target (0 = Aman, 1 = Malware)
MODEL_OUTPUT   = "otak_ai_pdf_rf.pkl"  # Nama file model yang akan disimpan
TEST_SIZE      = 0.20                 # 20% data untuk pengujian
RANDOM_STATE   = 42                   # Seed untuk reproduksibilitas


# ─────────────────────────────────────────────
#  FUNGSI: Muat dan Validasi Dataset
# ─────────────────────────────────────────────
def muat_dataset(path: str) -> pd.DataFrame:
    """
    Memuat dataset dari file CSV dan melakukan validasi awal.
    
    Args:
        path: Lokasi file CSV dataset.
    
    Returns:
        DataFrame yang sudah dimuat.
    """
    print(f"\n[*] Memuat dataset dari: '{path}' ...")
    
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"[ERROR] File dataset '{path}' tidak ditemukan!\n"
            "Pastikan file 'Final.csv' berada di direktori yang sama dengan train.py."
        )
    
    #buat ngelompati baris yang komanya cacat
    df = pd.read_csv(path, on_bad_lines='skip')
    print(f"    -> Dataset berhasil dimuat: {df.shape[0]} baris, {df.shape[1]} kolom")
    
    # Validasi kolom target
    if TARGET_COLUMN not in df.columns:
        raise ValueError(
            f"[ERROR] Kolom target '{TARGET_COLUMN}' tidak ditemukan di dataset!\n"
            f"Kolom yang tersedia: {list(df.columns)}"
        )
    
    # Tampilkan distribusi kelas
    distribusi = df[TARGET_COLUMN].value_counts()
    print(f"\n[*] Distribusi Kelas Target ('{TARGET_COLUMN}'):")
    for kelas, jumlah in distribusi.items():
        label = "Aman (Benign)" if kelas == 0 else "Malware"
        persen = (jumlah / len(df)) * 100
        print(f"    -> Kelas {kelas} [{label}]: {jumlah} sampel ({persen:.1f}%)")
    
    return df


# ─────────────────────────────────────────────
#  FUNGSI: Pra-Pemrosesan Data
# ─────────────────────────────────────────────
def praproses_data(df: pd.DataFrame):
    """
    Membersihkan data, menangani nilai kosong, dan memisahkan
    fitur (X) dari label target (y).
    
    Args:
        df: DataFrame mentah yang sudah dimuat.
    
    Returns:
        Tuple (X, y, feature_names)
    """
    print("\n[*] Melakukan pra-pemrosesan data ...")
    
    # Pisahkan fitur dan target
    X = df.drop(columns=[TARGET_COLUMN])
    y = df[TARGET_COLUMN]
    
    # Hapus kolom non-numerik yang tidak relevan (misal: nama file, hash, dll.)
    kolom_non_numerik = X.select_dtypes(include=["object"]).columns.tolist()
    if kolom_non_numerik:
        print(f"    -> Menghapus kolom non-numerik: {kolom_non_numerik}")
        X = X.drop(columns=kolom_non_numerik)
    
    # Tangani nilai yang hilang (NaN) dengan median kolom
    jumlah_nan = X.isnull().sum().sum()
    if jumlah_nan > 0:
        print(f"    -> Ditemukan {jumlah_nan} nilai NaN, mengisi dengan median kolom ...")
        X = X.fillna(X.median())
    else:
        print("    -> Tidak ada nilai NaN yang ditemukan.")
    
    # Pastikan label adalah integer (0 atau 1)
    y = y.map({'Benign': 0, 'Malicious': 1})
    
    feature_names = list(X.columns)
    print(f"    -> Total fitur yang digunakan: {len(feature_names)}")
    print(f"    -> Nama fitur: {feature_names[:10]}{'...' if len(feature_names) > 10 else ''}")
    
    return X, y, feature_names


# ─────────────────────────────────────────────
#  FUNGSI: Latih Model Random Forest
# ─────────────────────────────────────────────
def latih_model(X_train: pd.DataFrame, y_train: pd.Series) -> RandomForestClassifier:
    """
    Membuat dan melatih model Random Forest.
    """
    print("\n[*] Melatih model RandomForestClassifier ...")
    
    # Definisi model dengan hyperparameter Random Forest
    model = RandomForestClassifier(
        n_estimators=300,           # Jumlah pohon keputusan
        max_depth=6,                # Kedalaman maksimum setiap pohon
        class_weight="balanced",    # Otomatis seimbangin data Aman vs Malware (pengganti scale_pos_weight)
        random_state=RANDOM_STATE,
        n_jobs=-1                   # Gunakan semua core CPU
    )
    
    model.fit(X_train, y_train)
    print("    -> Pelatihan model selesai!")
    
    return model


# ─────────────────────────────────────────────
#  FUNGSI: Evaluasi Model
# ─────────────────────────────────────────────
def evaluasi_model(model: RandomForestClassifier, X_test: pd.DataFrame, y_test: pd.Series):
    """
    Mengevaluasi performa model pada data uji dan
    menampilkan laporan lengkap.
    
    Args:
        model: Model XGBoost yang sudah terlatih.
        X_test: Fitur data uji.
        y_test: Label data uji.
    """
    print("\n" + "="*55)
    print("  LAPORAN EVALUASI MODEL PDF-SHIELD")
    print("="*55)
    
    # Prediksi pada data uji
    y_pred  = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    # Metrik utama
    akurasi  = accuracy_score(y_test, y_pred)
    roc_auc  = roc_auc_score(y_test, y_proba)
    
    print(f"\n  Akurasi        : {akurasi*100:.2f}%")
    print(f"  ROC-AUC Score  : {roc_auc:.4f}")
    
    # Laporan klasifikasi lengkap
    print("\n  Laporan Klasifikasi:")
    print("-"*55)
    label_names = ["Aman (0)", "Malware (1)"]
    print(
        classification_report(
            y_test, y_pred,
            target_names=label_names,
            digits=4
        )
    )
    
    # Matriks konfusi
    cm = confusion_matrix(y_test, y_pred)
    print("  Matriks Konfusi:")
    print("-"*55)
    print(f"  {'':20s} Prediksi Aman  Prediksi Malware")
    print(f"  {'Aktual Aman':20s} {cm[0][0]:^14d} {cm[0][1]:^16d}")
    print(f"  {'Aktual Malware':20s} {cm[1][0]:^14d} {cm[1][1]:^16d}")
    
    # Cross-validation 5-fold
    print("\n[*] Menjalankan Cross-Validation 5-Fold ...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=RANDOM_STATE)
    # Gabungkan kembali train dan test untuk CV yang menyeluruh
    X_full = pd.concat([X_test])  # Menggunakan X_test sebagai proxy cepat
    cv_scores = cross_val_score(
        model,
        X_test, y_test,
        cv=cv,
        scoring="accuracy",
        n_jobs=-1
    )
    print(f"    -> Skor CV: {[f'{s:.4f}' for s in cv_scores]}")
    print(f"    -> Rata-rata: {cv_scores.mean()*100:.2f}% ± {cv_scores.std()*100:.2f}%")
    
    print("="*55)


# ─────────────────────────────────────────────
#  FUNGSI: Simpan Model
# ─────────────────────────────────────────────
def simpan_model(model: RandomForestClassifier, path: str, feature_names: list):
    """
    Menyimpan model terlatih beserta nama fitur ke dalam
    satu file .pkl menggunakan joblib.
    
    Args:
        model: Model XGBoost yang sudah terlatih.
        path: Path tujuan penyimpanan file model.
        feature_names: Daftar nama fitur training.
    """
    print(f"\n[*] Menyimpan model ke '{path}' ...")
    
    # Simpan model dan nama fitur bersama dalam satu dictionary
    artefak_model = {
        "model": model,
        "feature_names": feature_names,
        "versi": "1.0.0",
        "deskripsi": "PDF-Shield XGBoost Malware Detector"
    }
    
    joblib.dump(artefak_model, path)
    ukuran = os.path.getsize(path) / (1024 * 1024)  # Konversi ke MB
    print(f"    -> Model berhasil disimpan! Ukuran file: {ukuran:.2f} MB")


# ─────────────────────────────────────────────
#  PROGRAM UTAMA
# ─────────────────────────────────────────────
def main():
    print("\n" + "█"*55)
    print("  PDF-SHIELD: HYBRID AI MALWARE DETECTOR")
    print("  FASE 1 - PELATIHAN MODEL XGBoost")
    print("█"*55)
    
    # 1. Muat dataset
    df = muat_dataset(DATASET_PATH)
    
    # 2. Pra-pemrosesan data
    X, y, feature_names = praproses_data(df)
    
    # 3. Bagi data menjadi set latih dan uji
    print(f"\n[*] Membagi data ({int((1-TEST_SIZE)*100)}% latih / {int(TEST_SIZE*100)}% uji) ...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y  # Pertahankan proporsi kelas
    )
    print(f"    -> Data latih : {X_train.shape[0]} sampel")
    print(f"    -> Data uji   : {X_test.shape[0]} sampel")
    
    # 4. Latih model
    model = latih_model(X_train, y_train)
    
    # 5. Evaluasi model
    evaluasi_model(model, X_test, y_test)
    
    # 6. Simpan model
    simpan_model(model, MODEL_OUTPUT, feature_names)
    
    print("\n" + "█"*55)
    print("  PELATIHAN SELESAI!")
    print(f"  Model tersimpan di: '{MODEL_OUTPUT}'")
    print(f"  Jalankan 'streamlit run app.py' untuk memulai aplikasi.")
    print("█"*55 + "\n")


if __name__ == "__main__":
    main()
