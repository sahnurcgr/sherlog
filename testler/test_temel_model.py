"""Tespit katmani icin birim testleri. Calistirmak icin: py -m pytest testler"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tespit"))
from temel_model import log_satiri, metrikler, veriyi_yukle  # noqa: E402


def ornek_csv(yol: Path) -> Path:
    df = pd.DataFrame({
        "Flow ID": ["a", "b", "c", "d"],
        " Source IP": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        " Source Port": [5000, 5001, 5002, 5003],
        " Destination IP": ["10.0.0.9"] * 4,
        " Destination Port": [80, 22, 443, 21],
        " Protocol": [6, 6, 6, 6],
        " Timestamp": ["7/7/2017 1:00"] * 4,
        " Flow Duration": [100, 200, np.nan, 400],
        "Flow Bytes/s": [1.0, np.inf, 3.0, 4.0],
        " Label": ["BENIGN", "PortScan", "BENIGN", "PortScan"],
    })
    dosya = yol / "ornek.csv"
    df.to_csv(dosya, index=False)
    return dosya


def test_sonsuz_ve_eksik_satirlar_atilir_kayit_no_korunur(tmp_path):
    X, y, meta = veriyi_yukle(str(ornek_csv(tmp_path)), ornek=None)
    # 2. satirda sonsuz, 3. satirda eksik deger var: geriye 1. ve 4. satir kalir
    assert meta["kayit_no"].tolist() == ["L1", "L4"]
    assert y.tolist() == [0, 1]


def test_ip_port_ve_zaman_oznitelik_olarak_kullanilmaz(tmp_path):
    X, _, _ = veriyi_yukle(str(ornek_csv(tmp_path)), ornek=None)
    for sutun in ("Source IP", "Source Port", "Destination IP", "Timestamp", "Flow ID"):
        assert sutun not in X.columns
    assert "Destination Port" in X.columns


def test_yanlis_alarm_orani():
    gercek = [0, 0, 0, 0, 1, 1]
    tahmin = [1, 0, 0, 0, 1, 0]  # 4 normal kayittan 1'i yanlis alarm
    m = metrikler(gercek, tahmin)
    assert m["yanlis_alarm_orani"] == 0.25
    assert m["yanlis_alarm_sayisi"] == 1
    assert m["kacirilan_saldiri"] == 1


def test_log_satiri_ip_port_ve_zaman_icerir():
    satir = pd.Series({
        "Timestamp": "7/7/2017 1:55", "Source IP": "172.16.0.1", "Source Port": 54987,
        "Destination IP": "192.168.10.50", "Destination Port": 22, "Protocol": 6,
        "Total Fwd Packets": 2, "Total Backward Packets": 1, "Flow Duration": 591,
    })
    metin = log_satiri(satir)
    assert metin.startswith("7/7/2017 1:55 172.16.0.1:54987 -> 192.168.10.50:22")
    assert "sure_us=591" in metin
