<h1 align="center">CDSA — Çalışma Notları</h1>

<p align="center">
  <em>HTB Certified Defensive Security Analyst path'i boyunca tuttuğum modül notları</em>
</p>

<p align="center">
  <img alt="Dil" src="https://img.shields.io/badge/dil-T%C3%BCrk%C3%A7e-blue">
  <img alt="Alan" src="https://img.shields.io/badge/alan-Blue%20Team%20%2F%20SOC-informational">
  <img alt="Durum" src="https://img.shields.io/badge/durum-devam%20ediyor-yellow">
</p>

---

## Bu repo ne?

SOC Analyst yönünde ilerlerken çalıştığım her modül için **ayrı bir README** tutuyorum.
Amaç, modülü bitirdikten aylar sonra geri dönüldüğünde hâlâ işe yarayan bir referans
bırakmak — slayt özeti değil, karar verdiren notlar.

Her modül notu aynı iskeleti izler:

| Bölüm | Amacı |
|---|---|
| **Kavram tabloları** | Terim / tanım / örnek — tek bakışta ayrım |
| **Süreç ve akışlar** | Diyagramlar ASCII olarak, kopyalanabilir biçimde |
| **Key takeaways** | Modülün geriye kalan kısmı |
| **Sık karıştırılanlar** | Pratikte ve sınavda en çok tökezlenen noktalar |

Notlar Türkçe yazıldı; teknik terimler bilinçli olarak İngilizce bırakıldı — saha dili bu
şekilde ve terimleri çevirmek aramayı zorlaştırıyor.

---

## Modüller

| # | Modül | Konular | Durum |
|---|---|---|---|
| 01 | **[Incident Handling Process](./01-incident-handling-process/)** | NIST SP 800-61 lifecycle, Cyber Kill Chain, MITRE ATT&CK, Pyramid of Pain, TheHive, IOC standartları | ✅ Tamamlandı |
| 02 | Security Monitoring & SIEM Fundamentals | — | 🔜 Planlandı |
| 03 | Windows Event Logs & Finding Evil | — | 🔜 Planlandı |
| 04 | Introduction to Threat Hunting & Hunting With Elastic | — | 🔜 Planlandı |
| 05 | Understanding Log Sources & Investigating with Splunk | — | 🔜 Planlandı |
| 06 | Security Incident Reporting | — | 🔜 Planlandı |

> Liste modül çalıştıkça güncellenir.

---

## Yapı

```
CDSA/
├── README.md                          ← bu dosya (index)
└── 01-incident-handling-process/
    └── README.md                      ← modül notu
```

Her yeni modül `NN-modul-adi/README.md` olarak eklenir; yukarıdaki tablo da aynı anda
güncellenir.

---

## Kaynaklar

Notlar aşağıdaki kaynaklardan derlendi:

- **HTB Academy** — CDSA job role path modülleri
- **NIST SP 800-61** — *Computer Security Incident Handling Guide*
- **MITRE ATT&CK** — Enterprise Matrix
- **Lockheed Martin** — *Cyber Kill Chain*
- **David J. Bianco** — *The Pyramid of Pain*
- Sektör raporları: The DFIR Report, Unit 42 Global IR Report

---

<p align="center">
  <sub>Notlar kişisel çalışma amacıyla tutuldu ve halka açık paylaşıldı.<br>
  Hata veya eksik gördüğünüz yerler için issue açabilirsiniz.</sub>
</p>
