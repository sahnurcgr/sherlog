# Sherlog

**Siber güvenlik kayıtları için anomali tespiti ve yerel dil modeliyle kaynağa bağlı olay özeti.**

Sistem iki katmanlı bir boru hattıdır. Makine öğrenmesi modelleri ağ trafiği ve log kayıtlarında anomaliyi bulur; internetsiz çalışan yerel bir dil modeli, bulunan olayı her cümlesi ilgili log kaydına atıflı bir Türkçe özetle analiste açıklar. Tüm bileşenler tek makinede, internet bağlantısı olmadan çalışır.

## Durum

| Katman | Bileşen |
| --- | --- |
| Tespit | Veri ön işleme, kayıt numaralandırma | 
| Tespit | Random Forest ve Isolation Forest karşılaştırması | 
| Tespit | SHAP ile uyarı nedeni | 
| Dil modeli | Bağlam toplayıcı, yerel LLM, doğrulayıcı | 
| Arayüz | Analist arayüzü | 


## Ekip

- **Halime Şahnur Çöğür**: tespit katmanı (veri işleme, anomali tespiti, açıklanabilirlik)
- **Yağmur Kalyoncu**: dil modeli katmanı (bağlam, yerel LLM, çıktı doğrulama)

Danışman: Dr. Öğr. Üyesi Merve Özkan, Ankara Üniversitesi Bilgisayar Mühendisliği Bölümü
