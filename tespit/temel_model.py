"""
Sherlog - Tespit katmani: ilk temel model

CIC-IDS2017 akis kayitlari uzerinde iki yaklasimi ayni kosullarda karsilastirir:
  - Denetimli:   Random Forest (etiketli veriyle egitilir)
  - Denetimsiz:  Isolation Forest (yalnizca normal trafikle egitilir)

Ciktilar (sonuclar/ klasorune):
  - metrikler.json  : iki modelin kesinlik, duyarlilik, F1 ve yanlis alarm orani
  - uyarilar.json   : tespit edilen ilk olaylar, dil modeli katmaninin bekledigi bicimde
                      (uyari_id, puan, kayit numaralari, SHAP nedenleri)

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


def veriyi_yukle(yol: str, ornek: int | None):
    df = pd.read_csv(yol, low_memory=False)
    df.columns = df.columns.str.strip()  # CIC-IDS2017 sutun adlarinin basinda bosluk var

    # Her akis kaydina kalici bir kayit numarasi ver (dosyadaki satir sirasina gore).
    # Dil modeli katmani ozetteki her cumleyi bu numaraya baglayacak.
    df["kayit_no"] = [f"L{i + 1}" for i in range(len(df))]

    # Sonsuz ve eksik degerleri temizle (Flow Bytes/s gibi sutunlarda var)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    if ornek and len(df) > ornek:
        # Saldiri oranini koruyarak (tabakali) ornekle
        secilen, _ = train_test_split(
            df.index, train_size=ornek, stratify=df["Label"], random_state=RASTGELE
        )
        df = df.loc[secilen]

    etiket = df["Label"].astype(str).str.strip()
    y = (etiket != "BENIGN").astype(int)
    kayit_no = df["kayit_no"]
    X = df.drop(columns=["Label", "kayit_no"]).select_dtypes(include=[np.number])
    return X, y, kayit_no, etiket


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


def shap_nedenleri(model, X_ornek: pd.DataFrame, en_fazla: int = 3) -> list[list[dict]]:
    """Her uyari icin, karari en cok etkileyen oznitelikleri dondurur."""
    try:
        import shap
    except ImportError:
        # SHAP kurulu degilse modelin genel oznitelik onemine dus
        onem = pd.Series(model.feature_importances_, index=X_ornek.columns).nlargest(en_fazla)
        ortak = [{"oznitelik": k, "etki": round(float(v), 4)} for k, v in onem.items()]
        return [ortak for _ in range(len(X_ornek))]

    degerler = shap.TreeExplainer(model).shap_values(X_ornek)
    # shap surumune gore liste [sinif0, sinif1] ya da (n, oznitelik, sinif) dizisi gelir
    if isinstance(degerler, list):
        degerler = degerler[1]
    elif degerler.ndim == 3:
        degerler = degerler[:, :, 1]

    sonuc = []
    for satir in degerler:
        sira = np.argsort(-satir)[:en_fazla]
        sonuc.append(
            [{"oznitelik": X_ornek.columns[i], "etki": round(float(satir[i]), 4)} for i in sira]
        )
    return sonuc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="CIC-IDS2017 CSV dosyasi")
    ap.add_argument("--ornek", type=int, default=200_000, help="Kullanilacak en fazla satir")
    ap.add_argument("--cikti", default="sonuclar", help="Sonuc klasoru")
    ap.add_argument("--uyari-sayisi", type=int, default=10, help="uyarilar.json'a yazilacak olay")
    args = ap.parse_args()

    X, y, kayit_no, etiket = veriyi_yukle(args.csv, args.ornek)
    print(f"{len(X):,} kayit, {X.shape[1]} oznitelik, saldiri orani %{100 * y.mean():.2f}")

    X_tr, X_te, y_tr, y_te, no_tr, no_te, et_tr, et_te = train_test_split(
        X, y, kayit_no, etiket, test_size=0.3, stratify=y, random_state=RASTGELE
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

    # 3) Uyarilar: RF'nin en yuksek puanli tespitleri, SHAP nedenleriyle
    tespit = np.where(rf_tahmin == 1)[0]
    tespit = tespit[np.argsort(-rf_puan[tespit])][: args.uyari_sayisi]
    X_uyari = X_te.iloc[tespit]
    nedenler = shap_nedenleri(rf, X_uyari)

    uyarilar = []
    for sira, (i, neden) in enumerate(zip(tespit, nedenler), start=1):
        uyarilar.append({
            "uyari_id": f"U-{sira:04d}",
            "tur": et_te.iloc[i],          # gercek etiket; yalnizca kontrol icin
            "puan": round(float(rf_puan[i]), 4),
            "kayitlar": [no_te.iloc[i]],
            "nedenler": neden,
        })
    (cikti / "uyarilar.json").write_text(json.dumps(uyarilar, ensure_ascii=False, indent=2), "utf-8")
    print(f"\n{len(uyarilar)} uyari ve metrikler '{cikti}/' klasorune yazildi.")


if __name__ == "__main__":
    main()
