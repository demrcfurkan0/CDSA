[← Tüm modüller](../README.md)

# 04 — Introduction to Threat Hunting & Hunting With Elastic

> HTB CDSA path'inin dördüncü modülü için tuttuğum çalışma notları.
> Dwell time'dan hunting'in gerekçesine, sekiz aşamalı hunt sürecine, CTI kavramlarına
> (Diamond Model, Pyramid of Pain, üç intelligence katmanı) ve sonunda Elastic üzerinde
> uçtan uca yürütülen gerçek bir hunt'a — Stuxbot vakası.

Notlar Türkçe yazıldı, teknik terimler bilinçli olarak İngilizce bırakıldı.

---

## İçindekiler

**Bölüm I — Kavram**

1. [Threat Hunting Nedir](#1-threat-hunting-nedir)
2. [Threat Hunting Process](#2-threat-hunting-process)

**Bölüm II — Threat Intelligence**

3. [Glossary — CTI Kavramları](#3-glossary--cti-kavramları)
4. [Threat Intelligence Fundamentals](#4-threat-intelligence-fundamentals)

**Bölüm III — Pratik**

5. [Hunting for Stuxbot](#5-hunting-for-stuxbot)
6. [Tek Bakışta Özet](#6-tek-bakışta-özet)

---

# Bölüm I — Kavram

## 1. Threat Hunting Nedir

Başlangıç noktası **dwell time**: gerçek bir ihlal ile tespiti arasındaki **medyan** süre —
genelde haftalar, hatta aylar. Bu süre boyunca saldırgan ağda serbestçe dolaşır.

| Kavram | Tanım |
|---|---|
| **Threat hunting** | Aktif, insan-liderliğinde, sıklıkla hypothesis-driven bir pratik; mevcut güvenlik çözümlerini atlatan gizli, ileri tehditleri sistematik olarak arar |
| **Ana amaç** | Dwell time'ı azaltmak — kill chain'in en erken aşamasında kötü niyetliyi yakalamak |
| **Paradigma** | Reaktif (bekle-tepki ver) değil, **proaktif** |

> **Kritik ayrım:** threat hunting alert beklemez. Alert triaging'in tersine, hunter bir
> hipotezle yola çıkar ve arar. SOC tier yapısında bu **Tier 3**'ün işiydi.

**Süreç özeti:** yüksek değerli asset tespiti → muhtemel TTP analizi (threat intel'e
dayalı) → TTP artifact'lerini ve baseline'dan sapan anomalileri proaktif
tespit / izole / doğrula.

### 1.1 Hunting'in İki Modu

| Mod | Tetikleyici | Dayanak |
|---|---|---|
| **Proactive** | Hipotez, attacker TTP, intelligence | Anticipation (öngörü) |
| **Reactive** | Doğrulanmış bir incident | Evidence (kanıt) — ağda ilgili artifact aranır |

### 1.2 Hunter'da Olması Gereken Nitelikler

| Nitelik | Açıklama |
|---|---|
| **Threat landscape bilgisi** | Cyber tehditler, adversary TTP'leri, kill chain |
| **Cognitive empathy** | Saldırganla düşünsel empati — adversarial mindset |
| **Ortam bilgisi** | Network topolojisi, digital asset'ler, normal aktivite |
| **Veri ve araç** | High-fidelity data, tactical analytics, ileri hunting platformları |

### 1.3 Incident Handling ile İlişki

Hunter, IH'nin dört fazının hepsine dokunur:

| IH fazı | Hunter'ın rolü |
|---|---|
| **Preparation** | Net *rules of engagement* kurar; ne zaman/nasıl müdahale edileceğini belirler. Hunting mevcut IH policy'sine dokunabilir (ayrı policy gerekmeyebilir) |
| **Detection & Analysis** | **Vazgeçilmez.** IoC'nin gerçekten incident olup olmadığını belirler; adversarial mindset ile kaçırılmış artifact/IoC bulur |
| **Containment, Eradication, Recovery** | **Değişken** — bazı kurumlar hunter'dan bunu bekler, evrensel değil. Rol prosedür dokümanında belirlenir |
| **Post-Incident Activity** | Geniş uzmanlığıyla güvenlik duruşunu güçlendirecek öneriler sunar |

### 1.4 Threat Hunting Team — Sekiz Rol

| Rol | Odak |
|---|---|
| **Threat Hunter** | Çekirdek rol; TTP ve tespit metodolojisi derinliği, IoC arama |
| **Threat Intelligence Analyst** | Open-source, dark web, sektör raporu, threat feed toplama; gelecek trend tahmini |
| **Incident Responders** | Hunter tehdit bulunca devreye girer; investigation + containment/eradication/recovery |
| **Forensics Experts** | DFIR; malware analizi, reverse engineering, detaylı rapor |
| **Data Analysts/Scientists** | Büyük veri setleri; istatistik model, ML, data mining ile pattern çıkarma |
| **Security Engineers/Architects** | Güvenlik altyapısı tasarımı; hunter'la araç ve kill-chain defense implementasyonu |
| **Network Security Analyst** | Network davranışı ve trafik pattern'ı; normal akışı bilir, anomaliyi hızlı görür |
| **SOC Manager** | Ekip koordinasyonu ve organizasyonla iletişim |

### 1.5 Ne Zaman Hunt Edilir — Beş Tetikleyici

| Tetikleyici | Örnek |
|---|---|
| **Yeni adversary/vulnerability bilgisi** | Kullandığın uygulamada bilinmeyen bir zafiyet ortaya çıkarsa → hemen exploitation izi ara |
| **Bilinen adversary'ye yeni IoC** | Seni hedeflemiş bir grubun yeni IoC'leri yayınlanırsa → ağında izini ara |
| **Çoklu network anomalisi** | Aynı anda/kısa sürede birden çok anomali → sistemik sorun veya koordineli saldırı |
| **IR sırasında** | IR ekibi enfekte sistemle uğraşırken, hunter **diğer** compromised sistemleri arar |
| **Periodic proactive** | Savunmayı atlatmış latent tehditleri bulmak için düzenli egzersiz |

> Modülün mottosu: *"hunting için en doğru zaman her zaman şimdidir."* İlk dördü
> olay-tetikli, sonuncusu süreklidir.

### 1.6 Risk Assessment ile İlişki

Risk assessment, hunting'in **nereye odaklanacağını** belirler.
Adımları: asset identification → threat identification → vulnerability identification →
risk determination → mitigation strategy.

| Katkı | Nasıl |
|---|---|
| **Prioritizing** | En kritik asset'leri (crown jewels) belirleyip hunting'i oraya yoğunlaştırma |
| **Threat landscape** | Threat identification adımı TTP'leri anlamayı sağlar → hunting hypothesis kurulur |
| **Vulnerabilities** | Zayıflıkları öne çıkarır; örn. privilege escalation zafiyeti varsa user privilege anomalisi aranır |
| **Threat intelligence** | En olası threat actor'leri ve yöntemlerini belirleyerek intel uygulamasını yönlendirir |
| **IR plans** | Olası riskleri anlamak IR planını rafine eder |
| **Cybersecurity controls** | Mitigation stratejileri mevcut kontrolleri güçlendirir |

**Teknik araçlar:** vulnerability scanner, pentest araçları, threat intel platformları ve
SIEM (event aggregation + correlation ile holistik görünüm).

### 1.7 Key Takeaways

1. Threat hunting'in gerekçesi **dwell time** — saldırganın haftalarca fark edilmeden kalması.
2. Hunting insan-liderliğinde, hypothesis-driven, proaktif. **Alert beklemez.**
3. İki mod: **proactive** (hipotez/öngörü) ve **reactive** (doğrulanmış incident/kanıt).
4. Hunter'ın anahtar niteliği **cognitive empathy** — saldırgan gibi düşünmek.
5. Hunter IH'nin dört fazına da katkı verir; en kritik yer **Detection & Analysis**.
6. Beş tetikleyici var ama taban sürekli/periyodik hunting.
7. Risk assessment hunting'in önceliğini belirler — **crown jewels**'a odaklan.

### 1.8 Sık Karıştırılanlar

- **Threat hunting ≠ alert triaging.** Triaging alert'e tepki verir (reaktif, Tier 1). Hunting hipotezle arar (proaktif, Tier 3).
- **Hunter'ın CER fazındaki rolü evrensel değil** — kuruma göre değişir. "Hunter her zaman containment yapar" yanlış.
- **Proactive ve reactive hunting ikisi de threat hunting.** Reactive olması onu triaging yapmaz — fark, ağı incident'a bağlı artifact için taramak.
- **Risk assessment hunting'in girdisi, çıktısı değil.** Önce risk assessment, sonra ona göre hunting önceliği.
- **Dwell time bir medyan** — ortalama değil.

---

## 2. Threat Hunting Process

```
   ┌──────────────────┐   ┌───────────────────────┐   ┌──────────────────┐
   │ 1 Setting the    │──►│ 2 Formulating         │──►│ 3 Designing      │
   │   stage          │   │   hypotheses          │   │   the hunt       │
   └──────────────────┘   └───────────────────────┘   └────────┬─────────┘
            ▲                                                   ▼
   ┌────────┴─────────┐   ┌───────────────────────┐   ┌──────────────────┐
   │ 8 Continuous     │◄──│ 7 After the hunt      │◄──│ 4 Data gathering │◄┐
   │   learning       │   │                       │   │   & examination  │─┘ iteratif
   └──────────────────┘   └───────────────────────┘   └────────┬─────────┘
                                     ▲                          ▼
                          ┌──────────┴──────────┐   ┌──────────────────────┐
                          │ 6 Mitigating        │◄──│ 5 Evaluating/testing │
                          └─────────────────────┘   └──────────────────────┘
```

### 2.1 Sekiz Aşama + Emotet Karşılığı

| # | Aşama | Ne yapılır | Emotet örneği |
|---|---|---|---|
| 1 | **Setting the stage** | Hedef belirleme, extensive logging açma, SIEM/EDR/IDS kurulumu, threat actor profilleri | Emotet TTP'lerini araştırma; infection vector'leri (malicious attachment/link), hedeflenen asset'ler (admin endpoint, mail server) |
| 2 | **Formulating hypotheses** | Test edilebilir tahmin; threat intel, alert veya sezgiden | "Emotet, compromised email account'larla macro'lu Word döküman gönderiyor" |
| 3 | **Designing the hunt** | Veri kaynağı, metodoloji, aranacak IoC/pattern; custom script/query | Email/network/endpoint log'ları; Emotet C2 adresleri, file hash'leri; query ve correlation rule |
| 4 | **Data gathering & examination** | Aktif hunt; veri topla, analiz et. **Highly iterative** | Email log'unda şüpheli attachment pattern'ı, C2 ile iletişim; email header/network/behavioral analiz |
| 5 | **Evaluating & testing** | Sonuçları yorumla; hipotezi doğrula/çürüt, etkilenen sistem ve impact belirle | Benzer subject/attachment'lı email serisi → phishing doğrulandı; C2 bağlantısı → aktif enfeksiyon |
| 6 | **Mitigating** | İzole, malware temizle, patch, config değiştir | Etkilenen sistemi izole, endpoint protection deploy, compromised hesabı temizle, C2 domain'lerini blokla |
| 7 | **After the hunt** | Dokümante et ve paylaş; threat intel güncelle, detection rule geliştir, playbook rafine et | Yeni Emotet IoC'leri intel platformuna ekle, detection rule iyileştir |
| 8 | **Continuous learning** | Her döngü sonrakini besler; hipotez/metodoloji/araç geliştir | ML / behavioral detection ekleme, konferans/eğitim, diğer ekiplerle iş birliği |

### 2.2 Aşamalar Arası Kritik İlişkiler

| İlişki | Açıklama |
|---|---|
| **2 → 4** | Hipotez test edilebilir olmalı, yoksa aşama 4'te neyi arayacağını bilemezsin |
| **4 ⇄ 4** | Data gathering iteratif — yeni bilgi çıktıkça hipotez veya yaklaşım rafine edilir |
| **5** | Hipotez **çürütülebilir de** — bu başarısızlık değil, geçerli bir sonuç |
| **6 vs IH** | Mitigating, Incident Handling'in Containment-Eradication-Recovery'siyle örtüşür |
| **7 → 1** | After the hunt çıktısı (yeni IoC, rule, playbook) bir sonraki hunt'ın hazırlığını besler |

### 2.3 Key Takeaways

1. Süreç sekiz aşamalı ve **döngüsel** — continuous learning çekirdek prensip.
2. Hipotez **spesifik ve test edilebilir** olmalı ("APT web server zafiyetiyle C2 kuruyor" gibi).
3. Aşama 4 iteratif — hipotez süreç içinde değişebilir.
4. **Hipotezin çürütülmesi de geçerli sonuçtur.**
5. Mitigating, IH'nin CER fazıyla örtüşür.
6. After the hunt çıktısı detection rule ve playbook'a dönüşür — post-incident'ın hunting versiyonu.
7. Threat hunting *"art and science"* dengesi — teknik + yaratıcılık + ortam bilgisi.

### 2.4 Sık Karıştırılanlar

- **Test edilemeyen hipotez işe yaramaz.** "Ağda kötü bir şeyler var" hipotez değil. "X grubu Y zafiyetini kullanarak C2 kuruyor" hipotezdir.
- **Hipotezin çürütülmesi hunt'ın başarısızlığı değildir** — bir olasılığı elemek de değerli çıktıdır.
- **Aşama 6 her hunt'ta olmaz** — tehdit doğrulanırsa devreye girer. Çoğu hunt aşama 5'te "temiz" ile biter.
- **Setting the stage'deki logging ön koşuldur:** log yoksa aşama 4'te analiz edecek veri de yoktur. Threat hunting **logging olgunluğu** gerektirir.
- **After the hunt ≠ Continuous learning.** Biri bu hunt'ın dokümantasyonu/paylaşımı, diğeri süreçlerin uzun vadeli iyileştirilmesi.

---

# Bölüm II — Threat Intelligence

## 3. Glossary — CTI Kavramları

### 3.1 Çekirdek Terimler

| Terim | Tanım | Kritik nokta |
|---|---|---|
| **Adversary** | Seninle aynı hedefe (verine) sahip ama yetkisiz aktör | Kategoriler: cyber criminal, insider threat, hacktivist, state-sponsored |
| **APT** | Kapsamlı kaynağa sahip organize grup/nation-state; uzun süreli faaliyet | **"Advanced" teknik gelişmişlik demek değil** — stratejik planlama; "Persistent" = kaynakla desteklenen ısrar |
| **Campaign** | Benzer TTP ve collection requirement paylaşan incident'lar bütünü | Toplaması zaman ve emek ister |
| **Indicator** | Teknik veri + bağlam | Bağlamsız teknik veri savunmacı için değersiz |
| **IOC** | Aktif/geçmiş intrusion'dan gelen dijital iz | Hash, IP, URL, domain, malicious executable adı |

### 3.2 İki Formül

```
Data + Context = Indicator

Capability + Intent + Opportunity = Threat
```

| Bileşen | Anlamı |
|---|---|
| **Intent** | Saldırganı hedeflemeye iten gerekçe — corporate espionage, finansal kazanç, iş ilişkilerini hedefleme |
| **Capability** | Araç, kaynak, finansal destek + ağa sızma becerisi |
| **Opportunity** | Saldırıyı mümkün kılan koşullar — ele geçirilmiş email/credential, bilinen bir zafiyetin farkındalığı |

> Üçü de gerekli. Bir saldırgan yetenekli ve niyetli olabilir ama opportunity yoksa
> (zafiyet kapalı, credential sızmamış) threat gerçekleşmez. **Savunmanın işi genelde
> opportunity'yi ortadan kaldırmaktır** — patch, MFA, hardening.

### 3.3 TTP Hiyerarşisi — Soru Zamiriyle

| Katman | Soru | Açıklama |
|---|---|---|
| **Tactics** | *Why* | Stratejik hedef, yüksek seviye operasyon konsepti |
| **Techniques** | *How* | Tactic'e ulaşmak için genel yöntem — adım adım değil |
| **Procedures** | *Recipe* | Granüler, adım adım uygulama talimatı |

Örnek: spear-phishing ile initial access (**tactic**), belirli bir software zafiyetini
exploit etme (**technique**), o zafiyeti istismar etmenin tam adımları (**procedure**).

### 3.4 Pyramid of Pain — Tazeleme

Yaratıcısı: **David Bianco** (FireEye), *"Intel-Driven Detection and Response"* sunumu.
Aşağıdan yukarı: Hash (Trivial) → IP (Easy) → Domain (Simple) → Network/Host Artifacts
(Annoying) → Tools (Challenging) → TTPs (Tough).

| Katman | Bu bölümün eklediği detay |
|---|---|
| **Hash** | MD5/SHA-1/SHA-256; tek byte değişince hash tamamen değişir → en kırılgan |
| **IP** | IP spoofing, VPN, proxy, TOR ile gizlenir |
| **Domain** | **DGA** (Domain Generation Algorithm) ile binlerce pseudo-random domain; dynamic DNS ile hızlı IP değişimi |
| **Network artifacts** | Network log, packet capture, netflow, DNS log'da; trafik pattern'ı, unique packet header, olağandışı protokol |
| **Host artifacts** | System log, file system, registry key, running process, loaded DLL, volatile memory |
| **Tools** | Malware, exploit, script, C2 framework; sofistike saldırgan custom/modifiye araç kullanır |
| **TTPs** | Zirvede; değiştirmesi saldırgana en yüksek maliyeti getirir |

### 3.5 Diamond Model

Yaratıcılar: Sergio Caltagirone, Andrew Pendergast, Christopher Betz.

```
              Adversary
                 ╱ ╲
                ╱   ╲
     Capability ─────── Infrastructure
                ╲   ╱
                 ╲ ╱
               Victim
```

| Köşe | Temsil ettiği |
|---|---|
| **Adversary** | Intrusion'dan sorumlu kişi/grup/organizasyon; capability, motivation, intent |
| **Capability** | Kullanılan TTP'ler — malware, exploit, deployment yöntemleri |
| **Infrastructure** | Fiziksel/sanal kaynaklar — server, domain, IP, network resource (malware teslimi, C2, exfiltration) |
| **Victim** | Hedef — birey, organizasyon, sistem; zafiyetler, asset değeri, maruziyet |

**Meta-features:** Timestamp, Phase, Result, Direction, Methodology, Resources.

Dört köşe **bidirectional** oklarla bağlı: adversary, bir infrastructure üzerinden
capability kullanarak victim'i hedefler.

> **Örnek:** Finansal kurum (*Victim*), cybercriminal grup (*Adversary*) tarafından
> hedefleniyor; grup botnet'ten (*Infrastructure*) gönderilen spear-phishing (*Capability*)
> ile banking Trojan teslim ediyor.

### 3.6 Diamond Model vs Cyber Kill Chain

|  | **Cyber Kill Chain** | **Diamond Model** |
|---|---|---|
| **Odak** | Saldırının aşamaları (recon → actions on objectives) | Intrusion'ın bileşenleri ve ilişkileri |
| **Perspektif** | Lineer / zamansal | Holistik / ilişkisel |
| **İlişki** | İkisi birbirini tamamlar, rakip değil | |

### 3.7 Key Takeaways

1. İki formül: `Data + Context = Indicator`, `Capability + Intent + Opportunity = Threat`.
2. **Bağlamsız veri IOC değildir** — indicator'ı değerli kılan context.
3. APT'de "Advanced" teknik değil, **stratejik**; "Persistent" kaynakla desteklenen ısrar.
4. TTP hiyerarşisi: Tactics = *why*, Techniques = *how*, Procedures = *recipe*.
5. Pyramid of Pain'i David Bianco ortaya attı; yukarı çıkınca saldırgan maliyeti artar.
6. Diamond Model dört köşe (Adversary, Capability, Infrastructure, Victim) + meta-features.
7. Kill Chain zamansal, Diamond ilişkisel — birbirini tamamlar.

### 3.8 Sık Karıştırılanlar

- **APT ≠ teknik olarak gelişmiş.** En sık test edilen kavram yanılgısı.
- **Threat için üç bileşen de şart.** Capability + intent var ama opportunity yoksa threat yok.
- **Indicator ≠ IOC tam olarak.** Indicator = data + context (genel); IOC = intrusion'dan gelen spesifik artifact. IOC bir indicator türüdür.
- **Diamond Model'in köşelerini karıştırma:** Capability = TTP/araç, Infrastructure = server/domain/IP. Malware capability, onu barındıran server infrastructure.
- **DGA ve dynamic DNS**, domain'i neden "Simple to change" yaptığının sebebidir — sadece "domain kötü" demek yetmez.

---

## 4. Threat Intelligence Fundamentals

**Cyber Threat Intelligence** — savunmayı reaktiften proaktif/anticipatory hale getiren
asset. CTI ekibi SOC'a içgörü sağlar.

### 4.1 Dört Temel Kriter

| Kriter | Anlamı | Anahtar not |
|---|---|---|
| **Relevance** | Bilginin bizim organizasyonumuza uygunluğu | Kullanmadığımız bir yazılımın zafiyeti bizi ilgilendirmez |
| **Timeliness** | Hızlı iletim; bilgi zamanla değer kaybeder | *Aged* indicator artık kullanılmıyor olabilir veya çözülmüştür |
| **Actionability** | Savunma ekibine net aksiyon sunmalı | Aksi halde *"self-licking ice cream cone"* — kendini besleyen verimsiz döngü |
| **Accuracy** | Yayınlanmadan doğrulanmalı | Emin değilsen **confidence indicator** ile etiketle |

Dördü birleşince: adversary operasyonlarına içgörü, veri zenginleştirme, TTP keşfi ve
mitigation, karar vericilere bilgi.

### 4.2 Threat Intelligence vs Threat Hunting

|  | **Threat Intelligence** | **Threat Hunting** |
|---|---|---|
| **Doğası** | Predictive (öngörücü) | Reactive + Proactive |
| **Amaç** | Adversary'nin hamlesini tahmin etmek | Ağda adversary var mı / vardı mı araştırmak |
| **Sorduğu** | Nerede, ne zaman, hangi strateji, hangi hedef saldırı olacak | Bir tetikleyici sonrası: adversary tespitten kaçtı mı |
| **İlişki** | Adversary profili üretir → hunting'i besler | Bulguları → intel'i rafine eder |

> Intel öngörür, hunting doğrular; hunting bulur, intel öğrenir. Birbirini besler ama
> **birbirinin yerine geçmez.**

### 4.3 Üç Intelligence Katmanı

| Katman | Kitle | Soru | İçerik | Örnek |
|---|---|---|---|---|
| **Strategic** | C-suite, VP, liderler | *Who? Why?* | Zaman içindeki operasyona genel bakış, TTP + MO mapping, risk hizalama | APT28 (Fancy Bear) — geçmiş kampanyalar, motivasyon (political espionage), hedefler, uzun vadeli strateji |
| **Operational** | Mid-level yönetim | *How? Where?* | Kampanya detayı, TTP (strategic'ten daha ayrıntılı) | REvil ransomware kampanyası — initial access (phishing/exploit), lateral movement (credential dumping, admin tool), payload execution |
| **Tactical** | Network defender | Anlık aksiyon | Gerçekleşmiş/yakında gerçekleşecek saldırıların teknik detayı | REvil C2 IP/URL/domain'leri, sample hash'leri, file path, registry key, mutex, kod string'leri |

Üçü Venn gibi örtüşür: tactical operational'ı, operational strategic'i besler. Merkezde CTI
analisti en kapsamlı adversary portresini sunar.

### 4.4 Tactical CTI Raporu Nasıl Okunur — Yedi Adım

Emotet senaryosu üzerinden:

| # | Adım | Ne yapılır |
|---|---|---|
| 1 | **Scope & narrative** | Raporun makro bağlamını anla; tehdit bizim sektörümüze uygun mu |
| 2 | **IOC'leri sınıflandır** | **Network-based** (IP, domain), **Host-based** (hash, registry key), **Email-based** (adres, subject). Ek: mutex, SSL cert hash, API call, User-Agent, HTTP header, DNS pattern |
| 3 | **Attack lifecycle** | TTP'leri MITRE ATT&CK'a map'le; Emotet: spear-phishing → execution → persistence → defense evasion → C2 |
| 4 | **IOC analiz & doğrulama** | VirusTotal, AlienVault OTX ile çapraz kontrol; IOC yaşı, IP paylaşımı (cloud'da C2 IP'si meşru site de barındırabilir), kaynak güvenilirliği, false positive rate |
| 5 | **Security infrastructure'a entegre et** | Firewall rule, EDR'ye hash, IDS/IPS signature, email gateway. İş etkisini düşün — kritik servisi etkileyecekse **block yerine alert**; change management ile onayla |
| 6 | **Proactive threat hunting** | Sadece IOC arama değil — **TTP de ara**. Emotet PowerShell kullanır → IOC eşleşmese bile şüpheli PowerShell ara (varyantları yakalar) |
| 7 | **Continuous monitoring & learning** | Hit'leri izle, IR tetikle; kullanıcı eğitimi, detection rule iyileştir. Topluluğa geri katkı — yeni IOC/TTP'leri ISAC/ISAO'larla paylaş |

### 4.5 Key Takeaways

1. CTI'ın dört kriteri: **Relevance, Timeliness, Actionability, Accuracy**. Dördü birden gerekli.
2. Actionable olmayan intel = *"self-licking ice cream cone"*.
3. Threat Intelligence **predictive**, Threat Hunting **reactive + proactive**.
4. Üç katman soru zamiriyle ayrışır: Strategic *who/why*, Operational *how/where*, Tactical aksiyon.
5. Katmanlar Venn gibi örtüşür — tactical operational'ı, operational strategic'i besler.
6. IOC'leri Network/Host/Email olarak sınıflandır, VirusTotal/OTX ile doğrula.
7. Hunting IOC ile sınırlı değil — **TTP de aranır** (varyant yakalamak için).

### 4.6 Sık Karıştırılanlar

- **Threat Intelligence ≠ Threat Hunting.** En sık karıştırılan ikili.
- **Strategic ≠ Tactical.** Strategic C-suite için *who/why* (uzun vadeli); Tactical defender için IOC (anlık).
- **IOC entegrasyonunda her zaman block değil** — kritik servisi etkileyecekse alert tercih edilir. Change management şart.
- **Bir C2 IP'si meşru site de barındırabilir** (cloud IP sharing). Kör block iş kesintisi yaratır.
- **Hunting'i sadece IOC'ye indirgeme** — IOC değişir (Pyramid of Pain alt katmanları), TTP kalıcıdır.
- **Confidence indicator accuracy'nin parçası** — emin olmadığın intel'i yaymadan önce etiketle, silme.

---

# Bölüm III — Pratik

## 5. Hunting for Stuxbot

Uçtan uca gerçek bir hunt: Stuxbot IOC'leriyle başlayıp tüm attack chain'i Elastic'te
takip etme. Asıl öğretilen şey **hangi event ID ile hangi adımı bağladığın**.

### 5.1 Threat Intel Özeti

| Alan | Değer |
|---|---|
| **Grup** | Organize cybercrime, *"anyone, anytime"* — hedef gözetmez, fırsatçı |
| **Motivasyon** | Espionage (ransomware/finansal değil) |
| **Platform** | Microsoft Windows |
| **Impact** | Tam takeover / domain escalation |
| **Risk** | Critical |
| **Initial access** | Opportunistic phishing (social media, geçmiş breach, kurumsal site) |

**Attack chain:** Phishing email → OneNote file → Batch file → in-memory PowerShell → RAT
(persistence). **Lateral movement:** Microsoft-signed PsExec ve WinRM.

**Ortam:** ~200 kişilik online marketing firması. Gmail (web), Edge default browser,
TeamViewer remote support, AD GPO yönetimi.

| Index | İçerik |
|---|---|
| `windows*` | Windows audit + Sysmon + PowerShell log'ları |
| `zeek*` | Network security monitoring (DNS dahil) |

**Hipotez:** Başarılı phishing → malicious OneNote. Farklı bir hipotez (örn. hash eşleşen
binary execution) farklı bir sorgu sırası gerektirirdi.

### 5.2 Hunt Zinciri

```
invoice.one indirildi (Ev.15/11)
   → Zeek DNS ile kaynak doğrulandı (file.io)
   → OneNote açıldı (Ev.1)
   → cmd.exe → invoice.bat (Ev.1, parent zinciri)
   → PowerShell → Pastebin (Ev.1)
   → PID 9944 pivot (Ev.1,3,11,22) → Ngrok C2 + default.exe
   → SharpHound.exe (AD mapping)
   → hash pivot → PKI de compromised
   → 4625/4624 + LogonType 3 → svc-sql1 ile lateral movement
```

### 5.3 Adım Adım — Sorgu ve Bulgu

| # | Sorgu | Bulgu |
|---|---|---|
| 1 | `event.code:15 AND file.name:*invoice.one` | Event 15 (FileCreateStreamHash) = browser download. MSEdge ile, kullanıcının Downloads'ına |
| 2 | `event.code:11 AND file.name:invoice.one*` | Event 11 (File create) + `Zone.Identifier` → dosya internetten geldi. Host: WS001, IP 192.168.28.130 |
| 3 | `event.code:3 AND host.hostname:WS001` | IP doğrulama; ama download anında network connection **yok** — Sysmon browser trafiğini loglamıyor (yaygın config) |
| 4 | `source.ip:192.168.28.130 AND dns.question.name:*` (Zeek) | Gürültü filtrelenir. `mail.google.com` → `file.io` → SmartScreen scan. Bağlantı doğrulanır → dosya file.io'dan indirildi |
| 5 | `event.code:1 AND process.command_line:*invoice.one*` | OneNote 6 saniye sonra açıldı |
| 6 | `event.code:1 AND process.parent.name:"ONENOTE.EXE"` | 3 hit: biri zaman dışı, biri `OneNoteM.exe` (meşru), biri `cmd.exe` → `invoice.bat` |
| 7 | `event.code:1 AND process.parent.command_line:*invoice.bat*` | Tek hit: PowerShell → Pastebin'den indir ve çalıştır. Pastebin içeriği intel raporuyla eşleşiyor |
| 8 | `process.pid:"9944" and process.name:"powershell.exe"` | 17 hit. Event 1, 3, 11, 22 (DNSEvent). Ngrok C2 (443 = encrypted), `default.exe` drop, DC1'e DNS/bağlantı |
| 9 | `process.name:"default.exe"` | Ngrok C2, `svchost.exe` + `SharpHound.exe` upload. Ayrıca `payload.exe`, VBS |
| 10 | `process.name:"SharpHound.exe"` | 2 kez çalışmış, ~2 dk arayla, collection method `all` — AD attack path mapping |
| 11 | `process.hash.sha256:018d37…` | Hash intel raporuyla eşleşiyor. WS001 + PKI'da bulundu. `svc-sql1` profilinde backdoor → bu hesap compromised |
| 12 | `default.exe` parent (PKI'de) | Parent `PSEXESVC` → PsExec ile lateral movement. `user.name: svc-sql1` doğrulanır |
| 13 | `(event.code:4624 OR 4625) AND LogonType:3 AND source.ip:192.168.28.130` | `administrator` için 2 failed (4625), ardından `svc-sql1` için başarılı (4624) |

### 5.4 Bu Hunt'tan Çıkan Detection Dersleri

| Teknik detay | Anlamı |
|---|---|
| **Event 15 vs 11** | 15 = browser download (stream hash), 11 = genel file create. Browser yoksa 11 kullanılır |
| **Zone.Identifier** | Dosyanın internetten geldiğinin kanıtı (**MOTW** — Mark of the Web) |
| **Sysmon Event 3 boşluğu** | Browser trafiği loglanmaz → Zeek DNS devreye girer. İki kaynak birbirini tamamlar |
| **`process.parent` zinciri** | Attack chain'i parent-child ile ördün: OneNote → cmd → PowerShell |
| **PID ile pivot** | Tek PID (9944) üzerinden bir process'in tüm aktivitesini (Event 1, 3, 11, 22) topladın |
| **LogonType 3** | Network logon — lateral movement'ın imzası |
| **Hash ile yayılım** | Tek IOC (SHA256) ile kaç makinede olduğunu buldun → PKI de compromised |

### 5.5 Key Takeaways

1. Hunt bir **hipotezle** başlar; hipotez sorgu sırasını belirler.
2. IOC rapordan gelir ama rapordaki tek delivery'ye takılma — başka teknikler de aranır.
3. Event 15 → 11 → Zeek DNS: download'ı **üç kaynaktan** doğrula.
4. Attack chain **parent-child** ilişkisiyle örülür.
5. **PID pivot** bir process'in tüm izini tek sorguda toplar.
6. **Hash ile yatay arama** compromise'ın yayılımını ortaya çıkarır.
7. `4624`/`4625` + LogonType 3 brute force ve lateral movement'ı gösterir.

### 5.6 Sık Karıştırılanlar

- **Sysmon Event 3'ün boş olması saldırı yok demek değil** — browser trafiği bilerek loglanmıyor. Zeek olmadan bu adım kör kalır.
- **Wildcard konumu kritik:** `file.name:*invoice.one` (Event 15) vs `file.name:invoice.one*` (Event 11). `Zone.Identifier` suffix'ini atlarsan eşleşmez.
- **`svchost.exe` meşru Windows dosyasını taklit ediyor** — path (Temp, AppData) ve parent ile doğrula, isme güvenme.
- **Ngrok 443'e bağlanıyor = encrypted**, içeriği göremezsin. Ama DNS (`ngrok.io`) ve bağlantı pattern'ı yakalanır. C2'yi meşru domain arkasına gizleme taktiği.
- **Timestamp'ler arası zaman boşlukları** → scripted değil, insan etkileşimi işareti. Attribution için ipucu.
- **`administrator`'a brute force başarısız, `svc-sql1`'e başarılı** — saldırgan en zayıf yüksek-yetkili hesabı buldu. Service account'lar yine kritik.

---

## 6. Tek Bakışta Özet

| Konu | Tek cümlelik özü |
|---|---|
| **Threat hunting** | Alert beklemeyen, hipotezle arayan, dwell time'ı düşürmeyi hedefleyen proaktif pratik |
| **Hunt süreci** | 8 aşamalı döngü; hipotez test edilebilir olmalı, çürütülmesi de sonuçtur |
| **Threat formülü** | Capability + Intent + Opportunity; savunma opportunity'yi kapatır |
| **Pyramid of Pain** | IOC değişir, TTP kalıcıdır — yukarı çıktıkça saldırgan maliyeti artar |
| **Diamond Model** | Intrusion'ı Adversary/Capability/Infrastructure/Victim olarak yapılandırır |
| **CTI** | Relevance + Timeliness + Actionability + Accuracy; üç katman: strategic / operational / tactical |
| **Stuxbot hunt'ı** | Tek IOC'den başlayıp parent-child, PID ve hash pivot'larıyla tüm chain'i kurma |

**Hunt'ta kullanılan pivot teknikleri**

| Pivot | Ne yapar | Örnek |
|---|---|---|
| **Parent-child** | Attack chain'i adım adım kurar | `process.parent.name:"ONENOTE.EXE"` |
| **PID** | Tek process'in tüm aktivitesini toplar | `process.pid:"9944"` |
| **Hash** | Aynı binary'nin tüm makinelerdeki izini bulur | `process.hash.sha256:018d37…` |
| **IP / DNS** | Network tarafını Zeek ile doğrular | `source.ip:… AND dns.question.name:*` |
| **Logon** | Lateral movement'ı ortaya çıkarır | `event.code:4624 AND LogonType:3` |

---

## Kaynaklar

- HTB Academy — *Introduction to Threat Hunting & Hunting With Elastic* (CDSA path)
- David Bianco — *The Pyramid of Pain*, *Intel-Driven Detection and Response*
- Caltagirone, Pendergast, Betz — *The Diamond Model of Intrusion Analysis*
- Lockheed Martin — *Cyber Kill Chain*
- MITRE ATT&CK — Enterprise Matrix
- VirusTotal, AlienVault OTX — IOC doğrulama
- Elastic — Sysmon ve Zeek veri kaynakları, KQL

---

<p align="center">
  <a href="../README.md">← Tüm modüller</a>
</p>
