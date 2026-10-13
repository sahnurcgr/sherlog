"""
Sherlog - Tespit katmani: ilk temel model

CIC-IDS2017 akis kayitlari uzerinde iki yaklasimi ayni kosullarda karsilastirir:
  - Denetimli:   Random Forest (etiketli veriyle egitilir)
  - Denetimsiz:  Isolation Forest (yalnizca normal trafikle egitilir)

Ciktilar (sonuclar/ klasorune):
  - metrikler.json  : iki modelin kesinlik, duyarlilik, F1 ve yanlis alarm orani
  - uyarilar.json   : tespit edilen olaylar, dil modeli katmaninin bekledigi bicimde.
                      Ayni kaynak -> hedef ciftinden gelen supheli akislar tek uyarida
                      toplanir; her kayit numarasi, IP, port ve zaman bilgisiyle birlikte
                      okunabilir bir log satiri olarak yazilir.

Veri: CIC-IDS2017 "GeneratedLabelledFlows" (TrafficLabelling) surumu onerilir; bu surumde
IP adresi ve zaman damgasi vardir. "MachineLearningCSV" surumuyle de calisir, ancak o
zaman log satirlarinda IP ve zaman bulunmaz.

Kullanim:
  python tespit/temel_model.py --csv veri/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
"""

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

RASTGELE = 42

# Modele verilmeyen, yalnizca uyari ve log satiri icin tutulan sutunlar.
# IP, port numarasi ve zaman, modelin ezberlemesine yol acar; bu yuzden oznitelik degildir.
KIMLIK_SUTUNLARI = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Timestamp"]


def csv_oku(yol: str) -> pd.DataFrame:
    try:
        return pd.read_csv(yol, low_memory=False)
    except UnicodeDecodeError:
        # TrafficLabelling dosyalarinin bazilari latin-1 kodlamali
        return pd.read_csv(yol, low_memory=False, encoding="latin-1")


def veriyi_yukle(yol: str, ornek: int | None):
    df = csv_oku(yol)
    df.columns = df.columns.str.strip()  # CIC-IDS2017 sutun adlarinin basinda bosluk var
    df = df.dropna(subset=["Label"])

    # Her akis kaydina kalici bir kayit numarasi ver (dosyadaki satir sirasina gore).
    # Dil modeli katmani ozetteki her cumleyi bu numaraya baglayacak.
    df["kayit_no"] = [f"L{i + 1}" for i in range(len(df))]

    sayisal = df.drop(columns=["Label", "kayit_no"] + KIMLIK_SUTUNLARI, errors="ignore")
    sayisal = sayisal.select_dtypes(include=[np.number])
    # Sonsuz ve eksik degerleri temizle (Flow Bytes/s gibi sutunlarda var)
    temiz = ~sayisal.replace([np.inf, -np.inf], np.nan).isna().any(axis=1)
    df = df[temiz]

    if ornek and len(df) > ornek:
        # Saldiri oranini koruyarak (tabakali) ornekle
        secilen, _ = train_test_split(
            df.index, train_size=ornek, stratify=df["Label"], random_state=RASTGELE
        )
        df = df.loc[secilen]

    df["Label"] = df["Label"].astype(str).str.strip()
    y = (df["Label"] != "BENIGN").astype(int)
    X = sayisal.loc[df.index]
    meta = df[[c for c in ["kayit_no", "Label", *KIMLIK_SUTUNLARI, "Destination Port",
                           "Protocol", "Flow Duration", "Total Fwd Packets",
                           "Total Backward Packets"] if c in df.columns]]
    return X, y, meta


def metrikler(y_gercek, y_tahmin) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_gercek, y_tahmin, labels=[0, 1]).ravel()
    return {
        "kesinlik": round(precision_score(y_gercek, y_tahmin, zero_division=0), 4),
        "duyarlilik": round(recall_score(y_gercek, y_tahmin, zero_division=0), 4),
        "f1": round(f1_score(y_gercek, y_tahmin, zero_division=0), 4),
        "yanlis_alarm_orani": round(fp / (fp + tn) if (fp + tn) else 0.0, 4),
        "yanlis_alarm_sayisi": int(fp),
        "kacirilan_saldiri": int(fn),
        "test_ornegi": int(len(y_gercek)),
    }


def shap_degerleri(model, X: pd.DataFrame) -> np.ndarray | None:
    """Her satir icin 'saldiri' sinifina ait SHAP degerleri; SHAP yoksa None."""
    try:
        import shap
    except ImportError:
        return None
    degerler = shap.TreeExplainer(model).shap_values(X)
    # shap surumune gore liste [sinif0, sinif1] ya da (n, oznitelik, sinif) dizisi gelir
    if isinstance(degerler, list):
        return np.asarray(degerler[1])
    if degerler.ndim == 3:
        return degerler[:, :, 1]
    return degerler


def nedenler(model, X: pd.DataFrame, en_fazla: int = 3) -> list[dict]:
    """Bir uyarinin akislari icin, karari en cok etkileyen oznitelikler (ortalama SHAP)."""
    degerler = shap_degerleri(model, X)
    if degerler is None:
        onem = pd.Series(model.feature_importances_, index=X.columns).nlargest(en_fazla)
        return [{"oznitelik": k, "etki": round(float(v), 4)} for k, v in onem.items()]
    ortalama = degerler.mean(axis=0)
    sira = np.argsort(-ortalama)[:en_fazla]
    return [{"oznitelik": X.columns[i], "etki": round(float(ortalama[i]), 4)} for i in sira]


def log_satiri(m: pd.Series) -> str:
    """Bir akis kaydini dil modeline verilecek okunabilir bir satira cevirir."""
    zaman = f"{m['Timestamp']} " if "Timestamp" in m else ""
    kaynak = f"{m['Source IP']}:{m['Source Port']}" if "Source IP" in m else "?"
    hedef = f"{m['Destination IP']}:{m['Destination Port']}" if "Destination IP" in m \
        else f"port {m.get('Destination Port', '?')}"
    ek = []
    if "Protocol" in m:
        ek.append(f"proto={int(m['Protocol'])}")
    if "Total Fwd Packets" in m:
        ek.append(f"ileri_paket={int(m['Total Fwd Packets'])}")
    if "Total Backward Packets" in m:
        ek.append(f"geri_paket={int(m['Total Backward Packets'])}")
    if "Flow Duration" in m:
        ek.append(f"sure_us={int(m['Flow Duration'])}")
    return f"{zaman}{kaynak} -> {hedef} {' '.join(ek)}".strip()


def uyarilari_olustur(model, X_te, meta_te, puan, tahmin, uyari_sayisi, satir_sayisi):
    """Supheli akislari kaynak -> hedef ciftine gore gruplar; her grup bir uyari olur."""
    supheli = meta_te[tahmin == 1].copy()
    supheli["puan"] = puan[tahmin == 1]
    if supheli.empty:
        return []

    if {"Source IP", "Destination IP"} <= set(supheli.columns):
        anahtar = supheli["Source IP"].astype(str) + " -> " + supheli["Destination IP"].astype(str)
    else:
        anahtar = supheli["kayit_no"]  # IP yoksa her akis ayri uyari
    supheli["grup"] = anahtar

    gruplar = (supheli.groupby("grup")
               .agg(akis=("kayit_no", "size"), puan=("puan", "mean"))
               .sort_values(["akis", "puan"], ascending=False)
               .head(uyari_sayisi))

    uyarilar = []
    for sira, (grup, ozet) in enumerate(gruplar.iterrows(), start=1):
        akislar = supheli[supheli["grup"] == grup]
        if "Timestamp" in akislar:
            zaman = pd.to_datetime(akislar["Timestamp"], dayfirst=True, errors="coerce")
            akislar = akislar.assign(_zaman=zaman).sort_values("_zaman", kind="stable")
        gosterilen = akislar.head(satir_sayisi)
        neden_ornegi = X_te.loc[akislar.index[:200]]
        uyarilar.append({
            "uyari_id": f"U-{sira:04d}",
            "kaynak_hedef": grup,
            "akis_sayisi": int(ozet["akis"]),
            "puan": round(float(ozet["puan"]), 4),
            "gercek_etiket": akislar["Label"].mode().iat[0],  # yalnizca kontrol icin
            "kayitlar": gosterilen["kayit_no"].tolist(),
            "satirlar": [{"id": r["kayit_no"], "metin": log_satiri(r)}
                         for _, r in gosterilen.iterrows()],
            "nedenler": nedenler(model, neden_ornegi),
        })
    return uyarilar


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="CIC-IDS2017 CSV dosyasi")
    ap.add_argument("--ornek", type=int, default=200_000, help="Kullanilacak en fazla satir")
    ap.add_argument("--cikti", default="sonuclar", help="Sonuc klasoru")
    ap.add_argument("--uyari-sayisi", type=int, default=5, help="Yazilacak uyari sayisi")
    ap.add_argument("--satir-sayisi", type=int, default=20, help="Uyari basina log satiri")
    args = ap.parse_args()

    X, y, meta = veriyi_yukle(args.csv, args.ornek)
    print(f"{len(X):,} kayit, {X.shape[1]} oznitelik, saldiri orani %{100 * y.mean():.2f}")

    X_tr, X_te, y_tr, y_te, meta_tr, meta_te = train_test_split(
        X, y, meta, test_size=0.3, stratify=y, random_state=RASTGELE
    )

    # 1) Denetimli: Random Forest
    rf = RandomForestClassifier(
        n_estimators=100, class_weight="balanced", n_jobs=-1, random_state=RASTGELE
    )
    rf.fit(X_tr, y_tr)
    rf_puan = rf.predict_proba(X_te)[:, 1]
    rf_tahmin = (rf_puan >= 0.5).astype(int)

    # 2) Denetimsiz: Isolation Forest, yalnizca normal trafikle egitilir
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=RASTGELE, n_jobs=-1)
    iso.fit(X_tr[y_tr == 0])
    iso_tahmin = (iso.predict(X_te) == -1).astype(int)

    sonuc = {
        "veri": Path(args.csv).name,
        "kayit_sayisi": int(len(X)),
        "oznitelik_sayisi": int(X.shape[1]),
        "saldiri_orani": round(float(y.mean()), 4),
        "bolme": "%70 egitim / %30 test, tabakali, random_state=42",
        "random_forest": metrikler(y_te, rf_tahmin),
        "isolation_forest": metrikler(y_te, iso_tahmin),
    }

    cikti = Path(args.cikti)
    cikti.mkdir(parents=True, exist_ok=True)
    (cikti / "metrikler.json").write_text(json.dumps(sonuc, ensure_ascii=False, indent=2), "utf-8")

    print(f"\n{'Model':<18}{'Kesinlik':>10}{'Duyarlilik':>12}{'F1':>8}{'Yanlis alarm':>14}")
    for ad, anahtar in (("Random Forest", "random_forest"), ("Isolation Forest", "isolation_forest")):
        m = sonuc[anahtar]
        print(f"{ad:<18}{m['kesinlik']:>10.4f}{m['duyarlilik']:>12.4f}{m['f1']:>8.4f}"
              f"{m['yanlis_alarm_orani']:>14.4f}")

    # 3) Uyarilar: RF tespitleri, kaynak -> hedef ciftine gore gruplanmis, SHAP nedenleriyle
    uyarilar = uyarilari_olustur(rf, X_te, meta_te, rf_puan, rf_tahmin,
                                 args.uyari_sayisi, args.satir_sayisi)
    (cikti / "uyarilar.json").write_text(json.dumps(uyarilar, ensure_ascii=False, indent=2), "utf-8")
    print(f"\n{len(uyarilar)} uyari ve metrikler '{cikti}/' klasorune yazildi.")


if __name__ == "__main__":
    main()
