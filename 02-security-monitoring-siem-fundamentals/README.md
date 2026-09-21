[← Tüm modüller](../README.md)

# 02 — Security Monitoring & SIEM Fundamentals

> HTB CDSA path'inin ikinci modülü için tuttuğum çalışma notları.
> SIEM'in ne olduğu ve verinin içinden nasıl aktığı, SOC'un tier yapısı, MITRE ATT&CK'in
> security operations'taki yeri, Elastic Stack üzerinde KQL ile arama, detection rule
> geliştirme döngüsü, Kibana'da dashboard kurma ve alert triyajı.

Notlar Türkçe yazıldı, teknik terimler bilinçli olarak İngilizce bırakıldı.

---

## İçindekiler

**Bölüm I — Temeller**

1. [SIEM Nedir](#1-siem-nedir)
2. [SOC Nedir](#2-soc-nedir)
3. [MITRE ATT&CK & Security Operations](#3-mitre-attck--security-operations)

**Bölüm II — Araç: Elastic Stack**

4. [Mimari ve Bileşenler](#4-elastic-stack--mimari-ve-bileşenler)
5. [Kibana Discover ve KQL](#5-kibana-discover-ve-kql)
6. [Elastic Common Schema](#6-elastic-common-schema-ecs)

**Bölüm III — Pratik**

7. [SIEM Use Case Development](#7-siem-use-case-development)
8. [SIEM Visualization](#8-siem-visualization)
9. [Alert Triaging](#9-alert-triaging)
10. [Tek Bakışta Özet](#10-tek-bakışta-özet)

---

# Bölüm I — Temeller

## 1. SIEM Nedir

**Security Information and Event Management** — güvenlik verisi yönetimi ile güvenlik
olayı denetimini birleştiren yazılım/çözüm ailesi. Network donanımları ve uygulamalar
tarafından üretilen güvenlik alert'lerinin gerçek zamanlı değerlendirilmesini sağlar.

**Core fonksiyonlar:** log event toplama ve yönetimi, farklı kaynaklardan gelen log ve ek
verinin incelenmesi, ayrıca incident handling, dashboard ve dokümantasyon gibi operasyonel
özellikler.

### 1.1 Tarihçe — SIM + SEM = SIEM

|  | **SIM** (1. nesil) | **SEM** (2. nesil) |
|---|---|---|
| **Açılım** | Security Information Management | Security Event Management |
| **Temeli** | Geleneksel log collection management sistemleri | Güvenlik olaylarının işlenmesi |
| **Yaptığı** | Uzun süreli saklama, inceleme, log reporting + threat intelligence ile birleştirme | Consolidation, correlation, notification |
| **Kaynakları** | Log verisi | Antivirus, firewall, IDS; ayrıca authentication, SNMP trap, server ve database'lerin doğrudan bildirdiği event'ler |

"SIEM" terimi iki Gartner analistinin önerisiyle, 2005 tarihli *Enhance IT Security through
Vulnerability Management* raporunda ortaya çıktı.

### 1.2 Veri SIEM İçinde Nasıl Akar

```
┌──────────────────────┐   ┌───────────────────────────┐   ┌─────────────────────────────┐
│ 1. Data Ingestion    │──►│ 2. Normalization /        │──►│ 3. Analiz                   │
│    (collection)      │   │    Aggregation            │   │    detection rule, dashboard│
│  çeşitli log source  │   │  correlation engine'in    │   │    visualization, alert,    │
│                      │   │  anlayacağı ortak format  │   │    incident                 │
└──────────────────────┘   └───────────────────────────┘   └─────────────────────────────┘
        altyapı                    altyapı                          değer üretilen yer
```

| Aşama | Adı | Ne olur |
|---|---|---|
| 1 | **Data ingestion / collection** | SIEM çeşitli kaynaklardan log alır; her SIEM aracının kendine özgü toplama kabiliyetleri vardır |
| 2 | **Normalization / aggregation** | Ham veri, correlation engine'in anlayacağı biçime çevrilir; farklı veri setleri ortak formata dönüştürülür |
| 3 | **Analiz** | SOC ekibi normalize veriyi kullanarak detection rule, dashboard, visualization, alert ve incident oluşturur |

> Üçüncü adım modülde *"SIEM'in en kritik parçası"* olarak geçiyor — ilk ikisi altyapı,
> değer üreten kısım burası.

### 1.3 Dört Temel Use Case

| Use case | Özü | Kritik nokta |
|---|---|---|
| **Log aggregation & normalization** | Firewall, veritabanı ve kritik uygulamalardan terabaytlarca veriyi toplama | Merkezileştirme + korelasyon ile pattern, trend ve anomali görünür olur |
| **Threat alerting** | Advanced analytics + threat intelligence ile real-time alert üretme | Ekibe araştırıp mitigate edebileceği yeterli detayı vermek |
| **Contextualization & response** | Alert'i bağlamlandırma | Aşağıda |
| **Compliance** | Regülasyon gerekliliklerini karşılama | PCI DSS, HIPAA, GDPR — real-time monitoring ve trafik analizi zorunluluğu |

**Contextualization** en çok vurgulanan kısım. Mantığı: sadece alert üretmek yeterli değil.
Her olası güvenlik olayı için alert gönderen bir SIEM, ekibi alert hacmi altında boğar ve
false positive'ler sıradanlaşır.

Contextualization üç soruyu cevaplar:

| Soru | İngilizcesi |
|---|---|
| Olaya kim dahil | Actors involved |
| Network'ün hangi kısmı etkilendi | Affected parts |
| Ne zaman oldu | Timing |

Sonuç: gerçek tehditler ayırt edilir, otomatik konfigürasyon süreçleri bazı
bağlamlandırılmış tehditleri filtreleyerek ekibe ulaşan alert sayısını düşürür. İdeal SIEM,
araştırma sürerken operasyonları durdurarak tehdidi doğrudan yönetebilmeye izin verir.

### 1.4 SIEM'i IDS/IPS'ten Ayıran Şey

|  | **SIEM** | **IDS / IPS** |
|---|---|---|
| **Rolü** | Log verisini işler ve birleştirir, exploitation'a yol açabilecek event'leri tanır | Kendi alanında tespit/önleme yapar |
| **İlişki** | IDS/IPS'in yerini almaz, onlarla birlikte çalışır | SIEM'e log besler |
| **Ayırt edici kabiliyet** | High-risk event'leri doğru şekilde tespit edebilmek | — |

Bu yüzden **fine-tuning hayati**: her izlenen platform büyük hacimde event üretir, saatlik
event sayısı yüzlerden binlere çıkabilir.

Alert kanalları: e-mail, konsol pop-up, SMS, telefonla arama.

### 1.5 SIEM'siz vs SIEM'li

| SIEM yok | SIEM var |
|---|---|
| Log ve event'lere merkezi bakış yok | Merkezi dashboard, önceden belirlenmiş kategori ve event threshold'larına göre bildirim |
| Kritik event'ler gözden kaçar | Incident response süreci güçlenir |
| İncelenmeyi bekleyen event yığını birikir | Verimlilik artar |

İki somut örnek:

- Firewall 5 ardışık hatalı login kaydeder ve admin hesabı kilitlenir → durumu izlemek için tüm logları korele eden merkezi bir sistem gerekir.
- Web filtering yazılımı, bir bilgisayarın bir saatte 100 kez malicious siteye bağlandığını loglar → tek arayüzden görülüp aksiyon alınabilir.

**Regülasyon tarafı:** Banking, Finance, Insurance, Healthcare gibi sektörlerde on-prem
veya cloud'da managed SIEM zorunlu. SIEM; sistemlerin izlendiğine, loglandığına, gözden
geçirildiğine ve log retention policy'lerine uyulduğuna dair kanıt sunar.

### 1.6 Key Takeaways

1. SIEM = SIM (log saklama/raporlama) + SEM (event korelasyon/bildirim). 2005, Gartner.
2. Veri akışı üç adım: ingestion → normalization/aggregation → detection rule & alert.
3. Normalization'ın amacı correlation engine'in anlayacağı **ortak format** üretmek.
4. SIEM'i benzersiz kılan log toplamak değil, **high-risk event'i doğru tespit etmek**.
5. Alert üretmek yetmez — contextualization (kim, nerede, ne zaman) alert fatigue'i çözer.
6. SIEM, IDS/IPS'in yerini almaz; log'unu işler.
7. Regüle sektörlerde SIEM bir tercih değil, zorunluluk ve uyum kanıtıdır.

### 1.7 Sık Karıştırılanlar

- **SIM ≠ SEM.** SIM = information/storage/reporting, SEM = event/correlation/alerting.
- **Normalization ≠ aggregation.** Aynı adımda geçerler ama normalization formatı birleştirir, aggregation veriyi toplar.
- SIEM **"saldırıyı önler" demek yanlış** — tespit eder ve response'u hızlandırır. Önleme IPS'in işi.
- **Compliance bir yan fayda değil**, SIEM'in dört temel use case'inden biri.
- Alert sayısının çokluğu SIEM'in iyi çalıştığını göstermez; **tuning eksikliğini** gösterir.

---

## 2. SOC Nedir

Organizasyonun güvenlik durumunu sürekli izleyen ve değerlendiren uzman ekibi barındıran
tesis. Ana amaç: teknoloji çözümleri ile kapsamlı prosedürler bütününü birleştirerek siber
olayları tespit etmek, incelemek ve müdahale etmek.

> **Kritik sınır:** SOC ekibinin birincil işi kurumsal bilgi güvenliğinin *operasyonel*
> tarafını yürütmektir — güvenlik stratejisi geliştirmek, security architecture tasarlamak
> veya koruyucu önlemleri uygulamak değil.

| Kategori | İçerik |
|---|---|
| **Ekip** | Security analyst, engineer, manager |
| **Teknoloji** | SIEM, IDS/IPS, EDR |
| **Proaktif faaliyet** | Threat intelligence ve threat hunting |
| **Süreçler** | Incident triage, containment, elimination, recovery |
| **İleri kabiliyetler** | Forensic analysis ve malware analysis (bazı SOC'larda) |
| **İş birliği** | Incident response ekibiyle yakın çalışma |

### 2.1 Tier Yapısı

| Tier | Diğer adı | Sorumluluk | Ana hedef |
|---|---|---|---|
| **Tier 1** | First responder | Security event ve alert izleme, initial triage, üst tier'a escalation | Olayları hızlıca tespit edip önceliklendirmek |
| **Tier 2** | — | Escalate edilen olayların derin analizi, pattern ve trend tespiti, mitigation stratejisi geliştirme, bazen IR desteği | Monitoring tool'larını tune ederek false positive azaltmak |
| **Tier 3** | — | En karmaşık ve high-profile olaylar, proaktif threat hunting, gelişmiş detection/prevention stratejileri | Kurumun genel güvenlik duruşunu iyileştirmek |

> Tier sorumlulukları kurumun büyüklüğüne, sektörüne ve güvenlik gereksinimlerine göre
> değişir. Bu tablo genel bir çerçeve.

### 2.2 SOC Rolleri

| Rol | Sorumluluk |
|---|---|
| **SOC Director** | SOC'un genel yönetimi ve stratejik planlaması; bütçe, kadro, kurumsal güvenlik hedefleriyle hizalama |
| **SOC Manager** | Günlük operasyon, ekip yönetimi, incident response koordinasyonu, diğer departmanlarla iş birliği |
| **Tier 1 / 2 / 3 Analyst** | Yukarıdaki tablo |
| **Detection Engineer** | SIEM, IDS/IPS ve EDR için detection rule ve signature geliştirme, uygulama ve bakımı; analistlerle çalışarak detection coverage gap'lerini bulma |
| **Incident Responder** | Aktif olayları üstlenir; derinlemesine digital forensics, containment ve remediation; sistemleri geri getirme |
| **Threat Intelligence Analyst** | Threat intel verisini toplar, analiz eder, dağıtır; ekibin threat landscape'i anlamasını sağlar |
| **Security Engineer** | Güvenlik araç, teknoloji ve altyapısını geliştirir, deploy eder, bakımını yapar |
| **Compliance & Governance Specialist** | Standart, regülasyon ve best practice uyumu; audit ve reporting desteği |
| **Security Awareness & Training Coordinator** | Eğitim ve farkındalık programları; kurum içinde güvenlik kültürü |

### 2.3 SOC'un Evrimi — Üç Kuşak

|  | **SOC 1.0** | **SOC 2.0** | **Cognitive SOC** |
|---|---|---|---|
| **Köken** | Network Operation Center'dan türedi | Sofistike tehditlerin zorlamasıyla | SOC 2.0'ın eksiklerini kapatmak için |
| **Odak** | Network ve perimeter güvenliği | Intelligence temelli | Öğrenen sistemler |
| **Temel sorun** | Katmanlar arasında entegrasyon yok → korele olmayan alert'ler, birden çok platformda biriken görevler | — | Operasyonel deneyim ve business–security ekipleri arasında iş birliği eksikliği |
| **Tehdit tipi** | Tehditler başka vektörlere kayarken yaklaşım yerinde saydı | Multi-vector, persistent, asynchronous saldırılar; gizlenmiş IOC'ler | — |
| **Bileşenler** | Security intelligence platformu, identity management | Security telemetry + threat intelligence + network flow analysis + anomaly detection; layer-7 analysis ile low and slow saldırı tespiti | Güvenlik kararlarındaki deneyim boşluğunu telafi eden learning system'ler |
| **Ek vurgu** | — | Tam situational awareness; pre-event (vulnerability/configuration/dynamic risk management) ve post-event (IR + derin forensics) hazırlık; SOC'lar arası sektörel/ulusal iş birliği | Standart IR ve recovery prosedürlerinin eksikliğini gidermek |

SOC 2.0'ın tehdit odağı: malware (mobil varyantlar dahil) ve botnet'ler ana dağıtım
yöntemi. Botnet'lerin uzun ömürlülüğü, evrilen davranışı ve zamanla büyümesi threat
intelligence'ın odak noktası oldu.

### 2.4 Key Takeaways

1. SOC **operasyonu** yürütür; strateji, mimari ve koruma uygulaması onun işi değildir.
2. Tier 1 = first responder, hızlı tespit ve önceliklendirme. Tier 2 = derin analiz + tuning. Tier 3 = en karmaşık olaylar + threat hunting.
3. **Detection Engineer ayrı bir roldür** — rule ve signature yazar, coverage gap kapatır.
4. SOC 1.0'ın kusuru teknoloji eksikliği değil, **entegrasyon** eksikliğiydi.
5. SOC 2.0'ı tanımlayan kelime: **intelligence** (telemetry + threat intel + flow analysis + layer-7).
6. Cognitive SOC'un çözmeye çalıştığı şey teknoloji değil, **deneyim ve iş birliği** boşluğu.

### 2.5 Sık Karıştırılanlar

- **Tool tuning Tier 2'nin işidir**, Tier 1'in değil.
- **Threat hunting Tier 3'te** geçiyor; Tier 1'in görevi alert izlemek, aramak değil.
- SOC ekibi ile incident response ekibi **ayrı ekipler** olarak tarif ediliyor; SOC onlarla "yakın çalışır".
- Forensic ve malware analysis **her SOC'ta yok** — "bazı SOC'larda bulunan ileri kabiliyet".
- SOC 2.0'daki layer-7 analysis'in amacı özellikle **low and slow** saldırılar, genel trafik analizi değil.

---

## 3. MITRE ATT&CK & Security Operations

**ATT&CK** = Adversarial Tactics, Techniques, and Common Knowledge. Cyber threat
actor'ların TTP'lerini anlatan, düzenli güncellenen kapsamlı kaynak.

Framework farklı computing context'lere göre uyarlanmış matrisler içerir: **enterprise,
mobile, cloud**. Her matris, tactic'leri (saldırganın ulaşmak istediği hedef) ve
technique'leri (kullandığı yöntem) belirli TTP'lere bağlar.

### 3.1 Enterprise Matrix — 14 Tactic

| # | Tactic | Technique | Özü |
|---|---|---|---|
| 1 | Reconnaissance | 10 | Hedef hakkında bilgi toplama |
| 2 | Resource Development | 6 | Altyapı/hesap/kabiliyet edinme |
| 3 | Initial Access | 9 | Ortama ilk giriş |
| 4 | Execution | 10 | Kod çalıştırma |
| 5 | Persistence | 18 | Kalıcılık |
| 6 | Privilege Escalation | 12 | Yetki yükseltme |
| 7 | **Defense Evasion** | **37** | Tespitten kaçınma — en kalabalık tactic |
| 8 | Credential Access | 14 | Kimlik bilgisi elde etme |
| 9 | Discovery | 25 | Ortamı tanıma |
| 10 | Lateral Movement | 9 | Yanal hareket |
| 11 | Collection | 17 | Veri toplama |
| 12 | Command and Control | 16 | Uzaktan kontrol |
| 13 | Exfiltration | 9 | Veri dışarı çıkarma |
| 14 | Impact | 13 | Nihai etki |

> Technique sayılarının kendisi bir bilgi taşıyor: Defense Evasion 37 ile açık ara önde,
> Discovery 25 ikinci. Saldırganların en çok yöntem geliştirdiği alan tespitten kaçınmak —
> bu da detection engineering'in neden zor ve değerli olduğunu açıklıyor.

### 3.2 Security Operations'ta Sekiz Use Case

| Use case | Ne sağlar |
|---|---|
| **Detection and Response** | Bilinen attacker TTP'lerine dayalı detection ve response planı kurma; proaktif countermeasure geliştirme |
| **Security Evaluation & Gap Analysis** | Güvenlik duruşunun güçlü ve zayıf yanlarını tespit; security control yatırımlarını önceliklendirme |
| **SOC Maturity Assessment** | TTP'leri tespit/müdahale/mitigate edebilme kabiliyetini ölçerek SOC olgunluğunu değerlendirme |
| **Threat Intelligence** | Adversary davranışını tanımlamak için ortak dil ve format |
| **CTI Enrichment** | TTP'lere bağlam ekleme; potansiyel hedefler ve IOC'lere dair içgörü |
| **Behavioral Analytics Development** | TTP'leri somut kullanıcı ve sistem davranışlarına map'leyerek anomali tespit modeli kurma |
| **Red Teaming & Penetration Testing** | Gerçek saldırgan technique'lerini sistematik biçimde replike etme |
| **Training and Education** | Yapılandırılmış içerik sayesinde güvenlik profesyonellerini eğitme kaynağı |

ATT&CK'in asıl katkısı bir teknik liste olmaktan çok, adversary davranışını tanımlamak için
**paylaşılan bir dil ve yapı** sunması.

### 3.3 Key Takeaways

1. ATT&CK tek bir matris değil — enterprise, mobile, cloud gibi bağlamlara göre matrisler var.
2. Enterprise matriste 14 tactic var; sıralama Reconnaissance'tan Impact'e.
3. **Defense Evasion 37 technique** ile en geniş tactic.
4. Use case'ler sadece savunma değil — red team, eğitim ve olgunluk ölçümü de kapsıyor.
5. Framework'ün en büyük değeri: **ortak dil**.

### 3.4 Sık Karıştırılanlar

- **Tactic ≠ Technique.** Tactic = hedef (sütun başlığı), technique = yöntem.
- **Reconnaissance ve Resource Development**, saldırganın kurban ortamında olmadığı aşamalar. Log'unda bu iki tactic'e ait iz beklemek hatalıdır (Kill Chain'deki Weaponize mantığının ATT&CK karşılığı).
- **Threat Intelligence ≠ CTI Enrichment.** Biri ortak dil sağlamak, diğeri mevcut intel'e bağlam eklemek.
- **SOC Maturity Assessment bir denetim değil**, kabiliyet ölçümü — "hangi TTP'yi yakalayabiliyorsun" sorusu.

---

# Bölüm II — Araç: Elastic Stack

## 4. Elastic Stack — Mimari ve Bileşenler

```
┌───────┐    ┌──────────┐    ┌───────────────┐    ┌────────┐
│ Beats │───►│ Logstash │───►│ Elasticsearch │───►│ Kibana │
└───┬───┘    └──────────┘    └───────────────┘    └────────┘
    │                               ▲
    └───────────────────────────────┘
          (Logstash atlanabilir)
```

| Topoloji | Kullanım |
|---|---|
| Beats → Logstash → Elasticsearch → Kibana | Logstash'ta persistent queue, Elasticsearch'te Master / Data / ML node ayrımı |
| Beats → Elasticsearch → Kibana | Daha basit; Elasticsearch'te uniform node'lar |

| Bileşen | Rolü | Detay |
|---|---|---|
| **Elasticsearch** | Stack'in çekirdeği | Distributed, JSON-based search engine; RESTful API ile tasarlanmış. Indexing, storing, querying'i üstlenir |
| **Logstash** | Toplama, dönüştürme, taşıma | Farklı kaynaklardan gelen veriyi konsolide eder ve normalize eder |
| **Kibana** | Görselleştirme | Elasticsearch dokümanlarını gösterir, query çalıştırır; tablo, chart ve custom dashboard |
| **Beats** | Hafif data shipper | Uzak makinelere kurulan tek amaçlı taşıyıcılar; Logstash'a veya doğrudan Elasticsearch'e gönderir |

**Beats ailesi:** Filebeat, Winlogbeat, Heartbeat, Metricbeat, Packetbeat, Auditbeat
(+ File Spool Queue).

### 4.1 Logstash'in Üç İş Alanı

| # | Aşama | Ne yapar |
|---|---|---|
| 1 | **Process input** | Uzak konumlardan log kaydı alır, makine anlayacağı formata çevirir. Kaynaklar: flat file okuma, TCP socket, doğrudan syslog mesajları |
| 2 | **Transform & enrich** | Log kaydının formatını ve hatta içeriğini değiştirir; filter plugin'leri önceden tanımlı koşula göre ara işlem yapar |
| 3 | **Output** | Output plugin'leri ile kaydı Elasticsearch'e iletir |

**Ölçek ve dayanıklılık eklentileri**

| Amaç | Bileşen |
|---|---|
| Buffering ve resiliency | Kafka, RabbitMQ, Redis (messaging queue) |
| Güvenlik | nginx |

**Elasticsearch node rolleri:** Master (3), Ingest, Coordinating, Data – Hot, Data – Warm,
Alerting, Machine Learning (2+).

**Deployment:** SaaS (Elastic Cloud) veya Self Managed (Elastic Cloud Enterprise,
Standalone).

### 4.2 Elastic Stack'i SIEM Olarak Kullanmak

| Adım | Bileşen |
|---|---|
| Firewall, IDS/IPS, endpoint verisini ingest et | Logstash |
| Güvenlik verisini sakla ve indexle | Elasticsearch |
| Custom dashboard ve visualization oluştur | Kibana |
| Incident tespiti için search ve correlation yap | Elasticsearch |

> SOC analisti olarak birincil arayüzün **Kibana** olacak.

---

## 5. Kibana Discover ve KQL

### 5.1 Discover Arayüzü

| Eleman | İşlevi |
|---|---|
| **Index Pattern** | Hangi veri setinde arama yapılacağı (`zeek*`, `windows*`) |
| **Search Bar** | KQL sorgusu |
| **Time Picker** | Zaman aralığı |
| **Histogram** | Zaman içindeki hit dağılımı |
| **Document Table** | Ham kayıtlar |
| **Available fields** | Sol panelde mevcut alanlar ve sayısı |

> Index pattern değişince Available fields sayısı da değişir — `windows*` ile `zeek*` aynı
> alanlara sahip değil.

### 5.2 KQL Cheat Sheet

| Özellik | Syntax | Örnek | Anlamı |
|---|---|---|---|
| Temel yapı | `field:value` | `event.code:4625` | Windows failed login event'leri |
| Free text search | `"değer"` | `"svc-sql1"` | Herhangi bir indexed field'da bu string'i içeren kayıtlar |
| Logical operators | `AND` `OR` `NOT` `( )` | `event.code:4625 AND winlog.event_data.SubStatus:0xC0000072` | Disabled account'a karşı failed login |
| Comparison | `:` `:>` `:>=` `:<` `:<=` `:!` | `@timestamp >= "2023-03-03T00:00:00.000Z" AND @timestamp <= "2023-03-06T23:59:59.999Z"` | Tarih aralığı |
| Wildcard | `*` | `event.code:4625 AND user.name: admin*` | admin, administrator, admin123… |

### 5.3 Ezberlenecek İki Değer

| Değer | Anlamı |
|---|---|
| `4625` | Windows failed login attempt |
| `SubStatus: 0xC0000072` | Login başarısızlık nedeni: hesap disabled |

Bu ikisinin kombinasyonu neden önemli: **disabled bir hesaba karşı login denemesi**,
saldırganın o hesabın credential'ını bir şekilde ele geçirdiğini düşündürür.

`4625` tek başına: brute force, password guessing ve login'e ilişkin diğer şüpheli
aktiviteler. Sorgu source IP, username veya time range ile daraltılarak netleştirilir.

### 5.4 Alan ve Değer Nasıl Bulunur — İki Yaklaşım

| Yaklaşım | Yöntem |
|---|---|
| **1. Free text search + Discover** | Önce arama motorundan event'in ne olduğunu öğren, sonra Kibana'da `"4625"` diye ara, dönen kayıtlarda hangi field'ların bulunduğunu gör |
| **2. Elastic dokümantasyonu** | ECS, ECS event fields, Winlogbeat fields, Winlogbeat ECS fields, Winlogbeat security module fields, Filebeat fields, Filebeat ECS fields |

`"4625"` aramasında ortaya çıkan üç alan ve kaynakları:

| Alan | Kaynağı |
|---|---|
| `event.code` | ECS (Elastic Common Schema) |
| `winlog.event_id` | Winlogbeat |
| `@timestamp` | Orijinal event'ten çıkarılan zaman — `event.created` ile aynı şey değil |

`"0xC0000072"` aramasında kaydı genişletince görülen alan: `winlog.event_data.SubStatus`
(Winlogbeat kaynaklı). Aynı ekrandaki diğer `winlog.event_data.*` alanları investigation'da
işe yarar: `SubjectUserName`, `SubjectUserSid`, `SubjectDomainName`, `SubjectLogonId`,
`TargetUserName`, `TargetUserSid`, `TargetDomainName`.

---

## 6. Elastic Common Schema (ECS)

Elastic Stack genelinde event ve log'lar için paylaşılan ve genişletilebilir bir kelime
dağarcığı — farklı veri kaynakları arasında tutarlı field formatı sağlar.

| Avantaj | Açıklama |
|---|---|
| **Unified data view** | Windows log, network trafiği, endpoint event, cloud verisi — hepsi aynı field adlarıyla aranıp korele edilebilir |
| **Improved search efficiency** | Her veri kaynağı için ayrı field adı ezberlemeye gerek kalmaz |
| **Enhanced correlation** | Bir IP'yi network, firewall ve endpoint verisiyle çapraz ilişkilendirme |
| **Better visualizations** | Tutarlı isimlendirme dashboard kurmayı kolaylaştırır |
| **Interoperability** | Elastic Security, Observability ve Machine Learning ile tam uyum |
| **Future-proofing** | ECS temel şema olduğu için gelecek özelliklerle uyumluluk |

**Kural:** kurum Elastic Stack'i tüm ofis ve departmanlarda kullanıyorsa, sorgularda ECS
field'ları tercih edilmeli (yani `event.code`, `winlog.event_id` değil).

### 6.1 Key Takeaways

1. Üç ana bileşen: **Elasticsearch** (çekirdek, JSON + REST), **Logstash** (topla/dönüştür/taşı), **Kibana** (görselleştir). Beats dördüncü ama opsiyonel taşıyıcı.
2. İki topoloji var; Logstash atlanabilir.
3. Logstash'in gücü **normalization** — SIEM'in ikinci veri akışı adımının karşılığı.
4. KQL'in temeli `field:value`. Free text, mantıksal ve karşılaştırma operatörleri, wildcard destekler.
5. `4625` + `0xC0000072` = disabled hesaba failed login = araştırılması gereken davranış.
6. `event.code` ECS, `winlog.event_id` Winlogbeat — aynı değeri taşırlar, farklı şemalardan gelirler.
7. ECS kullan: korelasyon, arama verimliliği ve Elastic ürünleriyle uyumluluk için.

### 6.2 Sık Karıştırılanlar

- **`@timestamp` ≠ `event.created` ≠ `event.ingested`.** Biri olayın gerçekleştiği an, diğerleri kaydın oluşturulma/alınma anı. Timeline kurarken yanlışını seçersen saatler kayar.
- **Beats ≠ Logstash.** Beats hafif taşıyıcıdır, dönüştürme yapmaz. Transform işi Logstash'indir.
- **KQL, Elasticsearch'ün Query DSL'i değildir.** KQL Kibana'ya özgü ve daha sezgisel.
- **Free text search alan adı belirtmez** — tüm indexed field'larda arar. Hızlı keşif için iyi, production detection rule için kötü.
- **Kafka/Redis veri işlemez**, sadece buffer'lar. nginx ise güvenlik katmanı — ikisi de core bileşen değil.

---

# Bölüm III — Pratik

## 7. SIEM Use Case Development

Bir **SIEM use case**, belirli bir durumu tespit etmek için tanımlanan senaryodur.
Basitten karmaşığa uzanır: failed login denemelerinden ransomware outbreak tespitine.

**Korelasyon örneği:** bir kullanıcı için 10 ardışık failed authentication → SIEM bunları
tek bir event'e korele eder → "brute force" use case kategorisinde SOC ekibine alert üretir.

> Bu 10 event parolasını unutan gerçek kullanıcıdan da gelebilir, brute force yapan
> saldırgandan da. **SIEM ikisini ayırt etmez — ayırt etmek SOC ekibinin işidir.**

### 7.1 Use Case Development Lifecycle

```
Requirements → Data Points → Log Validation → Design & Implementation
      ▲                                                   │
      │                                                   ▼
      └──── Testing / Fine-tuning ◄── Onboarding ◄── Documentation
```

| Aşama | Ne yapılır | Brute force örneği |
|---|---|---|
| **Requirements** | Use case'in amacını ve hangi senaryoda alert isteneceğini netleştir. Talep müşteri, analist veya çalışandan gelebilir | "4 dakika içinde 10 ardışık login failure'da alert" |
| **Data Points** | Bir hesabın login olabileceği tüm noktaları tespit et; unauthorized access / login failure log'u üreten kaynakları topla | Windows, Linux, endpoint, server, application |
| **Log Validation** | Log'ların kritik bilgiyi içerdiğini doğrula; tüm authentication event'lerinde log geldiğini teyit et | Local, web-based, application, VPN, OWA authentication |
| **Design & Implementation** | Alert'in tetikleneceği koşulları tanımla — üç parametre: **Condition, Aggregation, Priority** | 4 dk'da 10 failure + false positive'i önlemek için aggregation + hedef kullanıcının yetkisine göre öncelik |
| **Documentation** | **SOP** (Standard Operating Procedure): analistin alert üzerinde izleyeceği standart süreç; condition, aggregation, priority, raporlanacak diğer ekipler ve escalation matrix | — |
| **Onboarding** | Önce development ortamı, sonra production. Gap'leri kapat, false positive'i düşür | — |
| **Testing / Fine-tuning** | Analistlerden düzenli geri bildirim; whitelisting ile correlation rule'ları güncel tut | — |

> Log validation'ın zorluğu: bir kullanıcı sadece Windows'a değil, VPN'e ve OWA'ya da login
> olur. Birini atlarsan detection coverage'ında delik bırakırsın.

### 7.2 Use Case Kurarken 10 Maddelik Checklist

| # | Madde |
|---|---|
| 1 | İhtiyaç ve riskleri anla, gerekli sistemler için alert kur |
| 2 | Priority ve impact belirle, alert'i Kill Chain veya MITRE'a map'le |
| 3 | **TTD** (Time to Detection) ve **TTR** (Time to Response) tanımla |
| 4 | Alert yönetimi için SOP yaz |
| 5 | Alert'lerin nasıl rafine edileceği sürecini tanımla |
| 6 | True positive'ler için **IRP** (Incident Response Plan) geliştir |
| 7 | Ekipler arası SLA ve OLA belirle |
| 8 | Alert yönetimi ve raporlama için audit süreci kur ve sürdür |
| 9 | Sistemlerin logging durumu, alert'lerin gerekçesi ve tetiklenme sıklığı için dokümantasyon oluştur |
| 10 | Case management araçları için knowledge base dokümanı oluştur |

TTD ve TTR, SIEM'in etkinliğini ve analist performansını ölçen metriklerdir.

### 7.3 İki Örnek — Aynı Technique, Farklı Severity

|  | **Örnek 1: MSBuild Started by Office App** | **Örnek 2: MSBuild Making Network Connections** |
|---|---|---|
| **Ne izliyor** | MSBuild'in Excel veya Word tarafından başlatılması | `MSBuild.exe`'nin outbound network connection kurması |
| **Neden şüpheli** | Office dokümanının malicious script payload çalıştırdığına işaret | Uzak/malicious IP'ye giden bağlantının arkasındaki process MSBuild |
| **Severity** | **HIGH** | **MEDIUM** |
| **Risk score** | 73 | 47 |
| **Gerekçe** | LOLBin kullanımı yüksek global risk kategorisi; baseline kurulduktan sonra bu çağrılar nadir ve kolay ayırt edilir | MSBuild meşru IP'ye de (örn. Microsoft update) bağlanabilir → daha çok false positive |
| **MITRE** | Defense Evasion (TA0005) + Execution (TA0002), `T1127`, `T1127.001` | Execution (TA0002), `T1127` |
| **Index pattern** | `winlogbeat-*` | `winlogbeat-*` |
| **Rule type / Schedule** | Query — 5 dakikada bir, 1 dakika look-back | Query — 5 dakikada bir, 1 dakika look-back |
| **SOP odağı** | `process.name`, `process.parent.name`, `event.action`, makine, kullanıcı, alert öncesi/sonrası ±2 gün kullanıcı aktivitesi | `event.action`, IP adresi ve IP reputation |

**Örnek 1 — custom query**

```kql
process.name:MSBuild.exe and process.parent.name:(eqnedt32.exe or excel.exe or fltldr.exe
  or msaccess.exe or mspub.exe or outlook.exe or powerpnt.exe or winword.exe)
  and event.action:"Process Create (rule: ProcessCreate)"
```

**Örnek 2 — custom query**

```kql
event.action:"Network connection detected (rule: NetworkConnect)"
  and process.name:MSBuild.exe
  and not destination.ip:(127.0.0.1 or "::1")
```

İki sorgudan çıkarılacak teknik dersler:

- **Parent process mantığı.** Örnek 1'in gücü `process.parent.name` listesinde. Office ailesinin tamamı sayılıyor (`eqnedt32.exe` = Equation Editor, klasik exploit hedefi).
- **Gürültü eleme.** Örnek 2'de `not destination.ip:(127.0.0.1 or "::1")` — localhost bağlantıları baştan eleniyor. Basit ama false positive'i ciddi düşüren bir hamle.
- **Look-back time.** 5 dakikada bir çalışan kural 1 dakika geriye de bakıyor; ingestion gecikmesi yüzünden kaçan event'leri yakalamak için.

**Fine-tuning mantığı:** Build Engine Windows geliştiricileri arasında yaygındır, ama
mühendis olmayanlarda olağandışıdır. Meşru parent process adlarını kuraldan hariç tutmak
false positive'i önler.

### 7.4 Key Takeaways

1. Use case = senaryo. **SIEM korele eder, karar SOC'undur.**
2. Lifecycle 9 aşamalı ve döngüsel; fine tuning yeni requirement doğurur.
3. Design'ın üç parametresi: **Condition, Aggregation, Priority**.
4. Log validation tüm authentication yollarını (local, web, app, VPN, OWA) kapsamalı.
5. Kural önce development, sonra production. Doğrudan production'a alınmaz.
6. TTD ve TTR, SIEM'in ve analistin performans ölçüsüdür.
7. Severity, technique'in tehlikeliliğine değil, **false positive olasılığına** göre de belirlenir.

### 7.5 Sık Karıştırılanlar

- **Aynı technique (`T1127`), iki farklı severity.** Fark tehdidin ciddiyeti değil, davranışın ne kadar nadir olduğu. Detection engineering'in özü bu.
- Örnek 1'de **iki tactic** var (Defense Evasion + Execution), Örnek 2'de bir tane. Bir use case birden çok tactic'e map'lenebilir.
- **Aggregation'ın amacı** alert'i güzelleştirmek değil, false positive'i önlemek.
- **SOP ≠ IRP.** SOP analistin alert üzerinde izleyeceği adımlar; IRP true positive çıkan olaya müdahale planı.
- **Whitelisting körlük yaratabilir** — meşru parent'ı hariç tutarken saldırganın o parent'ı taklit edebileceğini unutma.

---

## 8. SIEM Visualization

**Akış:** Dashboard → Create new dashboard → Create visualization → Time picker → Apply →
konfigürasyon → Save and return → Save (dashboard)

> İlk adım sık atlanıyor: time picker'ı geniş bir aralığa (örn. "Last 15 years")
> ayarlamadan veri görünmez, tablo boş kalır.

### 8.1 Visualization Penceresinde Dört Eleman

| # | Eleman | İşlevi |
|---|---|---|
| 1 | **Filter** | Grafik oluşturmadan önce veriyi filtreler |
| 2 | **Index pattern** | Hangi veri seti kullanılacak (network, Windows, Linux genelde ayrı index'lere bölünür) |
| 3 | **Search field names** | Bir field'ın veri setinde var olup olmadığını doğrulama |
| 4 | **Visualization type** | Grafik tipi (varsayılan: Bar vertical stacked) |

### 8.2 `.keyword` Kuralı

| Nerede | Kullanım |
|---|---|
| Rows / aggregation | `user.name.keyword` ✅ |
| KQL sorgusu | `user.name: svc-*` — `.keyword` kullanılmaz ✅ |

Kural basit: **aggregation yaparken `.keyword`, arama yaparken normal field.**

### 8.3 Dört Örnek — Yan Yana

|  | **Örnek 1** | **Örnek 2** | **Örnek 3** | **Örnek 4** |
|---|---|---|---|---|
| **Amaç** | Tüm failed logon'lar | Disabled hesaplara failed logon | Service account ile başarılı RDP | Local Administrators grubu değişiklikleri |
| **Event** | `4625` | `4625` | `4624` | `4732` / `4733` |
| **İkinci filtre** | — | `winlog.event_data.SubStatus: 0xc0000072` | `winlog.logon.type: RemoteInteractive` | `group.name is administrators` |
| **KQL** | `NOT user.name: *$ AND winlog.channel.keyword: Security` | — | `user.name: svc-*` | — |
| **Rows** | user, host, logon type | user, host | user, host, `related.ip` | user, MemberSid, group, action, host |
| **Hacim** | Yüksek — gürültü elemesi şart | Çok düşük | Çok düşük | Düşük |
| **Sinyal kalitesi** | Düşük, tuning gerektirir | Yüksek | Yüksek | Yüksek |

> Bölümün asıl dersi: dördü de aynı arayüzle, aynı dört adımla kuruldu. Ayrışan tek şey
> **hangi koşulu seçtiğin**.

### 8.4 Örnek 1 — Tüm Failed Logon'lar

**Rows**

| Field | Number of values | Rank by | Direction | Display name |
|---|---|---|---|---|
| `user.name.keyword` | 1000 | Alphabetical | Ascending | Username |
| `host.hostname.keyword` | 1000 | Count of records | Descending | Event logged by |
| `winlog.logon.type.keyword` | 1000 | Count of records | Descending | Logon Type |

**Metrics:** Function `Count`, Field `Records`, Display name `# of logins`, alignment Right.

> "Rank by"da ilk başta sadece Alphabetical görünür; *Count of records* seçeneği Metrics
> ayarlandıktan sonra gelir. Bu bir hata değil, sıralama meselesi.

**Beş iyileştirme talebi ve karşılıkları**

| İstek | Nasıl yapılır |
|---|---|
| Daha net kolon adları | Her Rows/Metrics ayarında **Display name** doldurulur |
| Logon Type eklensin | Rows'a `winlog.logon.type.keyword` eklenir |
| Sonuçlar sıralansın | Kolon başlığından Sort descending |
| Belirli host'lar izlenmesin | Her biri için ayrı filter: `user.name.keyword is not <değer>` |
| Computer account'lar izlenmesin | KQL: `NOT user.name: *$ AND winlog.channel.keyword: Security` |

Son satırdaki KQL'in iki parçası ayrı işler yapıyor:

| Parça | Ne yapar |
|---|---|
| `NOT user.name: *$` | Computer account'ları eler — Windows'ta makine hesapları `$` ile biter (`DC1$`, `WS001$`) |
| `AND winlog.channel.keyword: Security` | İlgisiz log'ların hesaba katılmamasını sağlar |

> Bölümün en değerli tek satırı. Computer account'ları izlemek iyi bir pratik değil —
> `DC1$`, `WS001$` gibi hesaplar sürekli network logon üretir ve tabloyu gürültüyle
> doldurur. Ham tabloda `DC2$` için 19.813 gibi sayılar görünürken, filtrelenince gerçek
> kullanıcılar ortaya çıkıyor.

### 8.5 Örnek 2 — Disabled Hesaba Failed Logon

**Neden "failed" kelimesi zorunlu:** disabled bir hesapla login mümkün değildir — doğru
credential girilse bile. Bu yüzden başarılı bir `4624` asla göremezsin, olay her zaman
`4625` olarak düşer. Windows başarısızlığın sebebini ayrıca `SubStatus` alanına yazar.

**Tehdit açısından anlamı:** doğru parola girilmiş olma ihtimali. Yani saldırgan o hesabın
credential'ını ele geçirmiş olabilir; hesap kapalı olduğu için şansı tutmamış.

| Katman | Ayar |
|---|---|
| Index pattern | `windows*` |
| Filter 1 | `event.code is 4625` |
| Filter 2 | `winlog.event_data.SubStatus is 0xc0000072` |
| Visualization type | Table |

**Rows:** `user.name.keyword` (disabled kullanıcı), `host.hostname.keyword` (denemenin
gerçekleştiği makine). **Metric:** Count / Records.

Sonuç tek satır olabilir — ve tam da bu yüzden değerli: hacim yok, sinyal var.

### 8.6 Örnek 3 — Service Account ile Başarılı RDP

**Neden bu bir tehdit göstergesi**

| Gerekçe | Açıklama |
|---|---|
| **Davranış kuralı** | Kurumsal ortamlarda service account credential'ları asla RDP logon için kullanılmaz |
| **Risk** | Service account'lar genelde istisnai derecede yüksek yetkiye sahiptir |
| **Bilgi kaynağı** | IT Operations bildirdi: ortamdaki tüm service account'lar `svc-` ile başlıyor |
| **Sonuç** | Service account'ların nasıl kullanıldığı yakından izlenmeli |

Bu, detection engineering'in temel kalıbı: **"normalde hiç olmaması gereken" bir davranışı
tanımla.** Eşik, istatistik veya baseline gerekmez — tek bir olay bile anlamlıdır.

> `svc-` ön eki bir yerden öğrenildi: IT Operations'tan. Detection rule yazarken **ortamın
> konvansiyonlarını bilmek, query yazmaktan önce gelir.**

| Katman | Ayar |
|---|---|
| Index pattern | `windows*` |
| Filter 1 | `event.code is 4624` |
| Filter 2 | `winlog.logon.type is RemoteInteractive` |
| KQL | `user.name: svc-*` |

**Rows**

| Sıra | Field | Display name | Ne gösterir |
|---|---|---|---|
| 1 | `user.name.keyword` | Username | Logon'u üreten service account |
| 2 | `host.hostname.keyword` | Connect to | Logon'un gerçekleştiği makine (olayı raporlayan) |
| 3 | `related.ip.keyword` | Connect from | Logon'u başlatan makinenin IP'si |

> **Connect to / Connect from ayrımı** bu örneğin en öğretici kısmı: bir logon olayında iki
> taraf vardır. `host.hostname` olayı loglayan (hedef) makine, `related.ip` bağlantıyı
> başlatan (kaynak) taraf. Lateral movement araştırmasında bu iki alan olmadan hiçbir yere
> varamazsın.

**Filter vs KQL — ne zaman hangisi**

|  | Filter | KQL search bar |
|---|---|---|
| Bu örnekte | `event.code`, `winlog.logon.type` — tam eşleşme | `user.name: svc-*` — wildcard |
| Neden | Sabit, bilinen değerler için görsel ve tıklanabilir | Pattern eşleştirme gerektiren durumlar |

### 8.7 Örnek 4 — Administrators Grubu Değişiklikleri

| Event | Anlamı |
|---|---|
| `4732` | A member was added to a security-enabled local group |
| `4733` | A member was removed from a security-enabled local group |

**Neden izlenir:** local Administrators grubuna hesap eklemek klasik bir persistence ve
privilege escalation adımıdır.

**Filtreler**

| Filter | Operatör | Değer |
|---|---|---|
| `event.code` | **is one of** | `4732`, `4733` |
| `group.name` | is | `administrators` |

`is one of` operatörü tek filtrede birden fazla değer alır ve `AND` değil **`OR`**
mantığıyla çalışır.

**Rows — her kolon bir soruya cevap**

| Soru | Field |
|---|---|
| İşlemi **kim** yaptı | `user.name.keyword` |
| Hangi **kullanıcı** eklendi/çıkarıldı | `winlog.event_data.MemberSid.keyword` |
| Hangi **gruba** | `group.name.keyword` |
| **Eklendi mi çıkarıldı mı** | `event.action.keyword` |
| Hangi **makinede** | `host.name.keyword` |
| **Kaç kez** | Metric: Count |

> Bu tablo tek bir olayı beş soruyla çevreliyor: kim, kimi, nereye, ne yaptı, nerede.
> Incident Handling modülündeki *who / what / when / where* disiplininin log tarafındaki
> karşılığı.

**Panel bazlı zaman aralığı:** dashboard'un genel zaman aralığından bağımsız olarak tek bir
panele kendi aralığını verebilirsin.
Yol: panel gear ikonu → More → Customize time range → tarih seç → dashboard'u Save et.

**Absolute time range uyarısı**

| Kullanım | Sonuç |
|---|---|
| Absolute (1 Ocak – 31 Ocak 2023) | Bucket günlük aralıkta çalışır ✅ |
| Relative ("last 15 years" vb.) | Bucket haftalık aralığa kayabilir ❌ |

Elasticsearch veriyi bucket'lara göre topladığı için, gerçek bir visualization kurarken
tarih aralığı elle belirlenmeli. Aksi halde grafik doğru görünür ama **gruplama yanlıştır**.

### 8.8 Key Takeaways

1. Dashboard = container, içinde birden çok visualization barındırır.
2. **Filter** veriyi grafik oluşturmadan önce daraltır; **KQL search bar** sonradan uygulanır. İkisi farklı katman.
3. Aggregation için `.keyword` zorunlu.
4. **Rows** = gruplama boyutları, **Metrics** = ölçüm. Table'da her Rows bir kolon olur.
5. Display name sadece kozmetik değil — dashboard'u başkası okuyacak.
6. Computer account'ları (`$`) elemek, Windows logon analizinde standart hijyen.
7. Refinement döngüsel: kaydet, bak, gürültüyü gör, filtrele, tekrar kaydet.

### 8.9 Sık Karıştırılanlar

- **Time picker'ı ayarlamadan hiçbir şey görünmez.** Veri yok sanma.
- **`user.name` ≠ `user.name.keyword`.** Aggregation'da yanlışını seçersen ya hata alırsın ya saçma sonuç.
- `4625` tablosundaki yüksek sayılar mutlaka saldırı değil — **computer account gürültüsü** olabilir. Önce filtrele, sonra yorumla.
- **`is not` filtresi ile KQL `NOT` aynı işi yapar** ama farklı yerlerde durur.
- **Visualization'ı kaydetmek (Save and return) dashboard'u kaydetmez.** İki ayrı Save var.
- Filtre değerinde `0xc0000072` küçük harfle yazılıyor; büyük harfle yazarsan eşleşmeyebilir — Discover'da doğrula.
- **`SubStatus` ≠ `Status`.** Status genel başarısızlık kodunu, SubStatus ayrıntılı nedeni verir.
- `winlog.event_data.SubStatus` **Winlogbeat alanıdır, ECS değil.** ECS karşılığı yok.
- `4624` tek başına gürültü; değeri logon type ve kullanıcı filtresiyle daraltıldığında kazanır.
- `RemoteInteractive` **metin alanıdır** (sayısal karşılığı Logon Type 10), büyük/küçük harfe duyarlı yazılır.
- `related.ip` birden fazla IP içerebilen bir **ECS alanıdır** — olaydaki tüm ilgili IP'leri toplar, sadece kaynağı değil.
- **`4732`/`4733` local group olaylarıdır.** Domain grupları için ID'ler farklı: `4728`/`4729` global, `4756`/`4757` universal.
- **`host.name` ≠ `host.hostname`.** `host.name` genelde yapılandırılmış ad, `host.hostname` sistemin bildirdiği ad. Discover'da kontrol et.
- `MemberSid` bir **SID** döndürür (`S-1-5-21-…`), okunabilir kullanıcı adı değil.
- Tabloda `ANONYMOUS LOGON` satırı görünüyorsa bu **tek başına alarm sebebi**.

**SID → isim çevirimi (PowerShell)**

```powershell
(New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-...")).Translate([System.Security.Principal.NTAccount])
```

---

## 9. Alert Triaging

Çeşitli monitoring ve detection sistemlerinin ürettiği alert'leri **değerlendirme ve
önceliklendirme** süreci. Amaç: tehdit seviyesini ve kuruma olası etkisini belirlemek,
böylece kaynakları doğru dağıtmak.

Modül 12 adım veriyor; bunları dört faza ayırmak akılda tutmayı kolaylaştırıyor.

### 9.1 Faz 1 — Anlama

| Adım | Yapılacaklar |
|---|---|
| **Initial Alert Review** | Metadata, timestamp, source IP, destination IP, etkilenen sistemler, tetikleyen rule/signature. İlişkili log'ları (network, system, application) analiz ederek bağlamı kur |
| **Alert Classification** | Kurumun önceden tanımlı sınıflandırma sistemine göre severity, impact ve urgency ile sınıflandır |
| **Alert Correlation** | Alert'i ilişkili alert/event/incident'larla çapraz kontrol et; pattern, benzerlik ve IOC ara. SIEM'i sorgula, threat intelligence feed'lerine bak |
| **Enrichment** | Network packet capture, memory dump, file sample topla. Şüpheli dosya/URL/IP'yi harici threat intel, açık kaynak araç veya sandbox ile analiz et |

### 9.2 Faz 2 — Değerlendirme

| Adım | Neyi ölçer |
|---|---|
| **Risk Assessment** | Kritik asset, veri ve altyapıya olası risk ve etki. Etkilenen sistemlerin değeri, verinin hassasiyeti, compliance etkileri. Saldırının başarılı olma ve lateral movement olasılığı |
| **Contextual Analysis** | Etkilenen asset'lerin kritikliği; mevcut güvenlik kontrollerinin (firewall, IDS/IPS, endpoint protection) durumu; compliance ve sözleşme yükümlülükleri |

> Contextual analysis'in en değerli sorusu: **alert, bir kontrolün başarısız olduğunu mu
> yoksa saldırganın onu atlattığını mı gösteriyor?** İkisi farklı müdahale gerektirir.

### 9.3 Faz 3 — Aksiyon

| Adım | İçerik |
|---|---|
| **Incident Response Planning** | Alert anlamlıysa IRP'yi başlat. Alert detayları, etkilenen sistemler, gözlenen davranışlar, olası IOC'ler ve enrichment verisi dokümante edilir. IR ekibine rol ve sorumluluk atanır |
| **Consultation with IT Operations** | Eksik bağlamı IT operations'tan al: etkilenen sistemler, yakın zamandaki değişiklikler, süregelen bakım faaliyetleri. Bilinen sorunlar, misconfiguration veya network değişiklikleri false positive üretebilir |
| **Response Execution** | Ek bağlam alert'i çözüyorsa veya non-malicious olduğunu gösteriyorsa → escalation'sız kapat. Hâlâ şüphe varsa → incident response adımlarına geç |

> **IT Operations danışması** modülün özellikle durduğu adım. Bir alert'in arkasında
> saldırgan değil, dün gece yapılan bir bakım olabilir. Bunu sormadan escalate etmek hem
> zaman kaybı hem güven kaybı.

### 9.4 Faz 4 — Yönetim

| Adım | İçerik |
|---|---|
| **Escalation** | Kurum politikası ve alert severity'sine göre tetikleyicileri belirle. Escalate ederken kapsamlı özet ver: severity, olası etki, enrichment verisi, risk assessment. Yasal/regülatif gereklilik varsa dış kurumlara da escalate et (law enforcement, IR sağlayıcıları, CERT'ler) |
| **Continuous Monitoring** | Durumu ve IR ilerleyişini izlemeye devam et; gelişme, bulgu veya severity değişikliklerini ilet |
| **De-escalation** | Risk azaldı, incident contain edildi ve daha fazla escalation gereksizse de-escalate et. İlgili taraflara alınan aksiyonlar, sonuçlar ve lessons learned özetiyle bildir |

**Escalation tetikleyicileri**

| # | Tetikleyici |
|---|---|
| 1 | Kritik sistem/asset'in compromise olması |
| 2 | Devam eden saldırı |
| 3 | Tanıdık olmayan / sofistike teknikler |
| 4 | Yaygın etki (widespread impact) |
| 5 | Insider threat |

> Escalation değerlendirmesinde sorulacak asıl soru: **escalate edilmezse sonuçları ne olur?**

### 9.5 Key Takeaways

1. Triaging = değerlendirme + önceliklendirme. Amaç kaynak dağılımı.
2. Escalation, kararı yetkisi olan kişiye taşımaktır — analistin yükünü atması değil.
3. **Correlation ve enrichment ayrı adımlar**: biri ilişki kurar, diğeri bağlam ekler.
4. IT Operations danışması, false positive'lerin en büyük kaynağını (planlı değişiklikler) kapatır.
5. Ek bağlam alert'i çözüyorsa → escalation'sız kapatılır. **Her alert yukarı gitmez.**
6. De-escalation da sürecin resmi bir parçasıdır ve lessons learned özetiyle biter.
7. Süreç düzenli olarak gözden geçirilip yeni tehditlere uyarlanır.

### 9.6 Sık Karıştırılanlar

- **Classification ≠ Risk assessment.** Classification önceden tanımlı sisteme göre etiketleme; risk assessment asset değeri ve olasılık üzerinden değerlendirme.
- Escalation'da **"alert var" demek yetmez** — severity, etki, enrichment verisi ve risk assessment birlikte iletilir.
- **Dış escalation** (law enforcement, CERT) analistin inisiyatifi değil, yasal/regülatif gereklilik meselesidir.
- **Alert'i kapatmak da bir karardır** ve dokümante edilir. "False positive'di, geçtim" kabul edilebilir değil.
- **De-escalation'ın koşulu "alert azaldı" değil**: risk mitigate edildi + incident contain edildi.

---

## 10. Tek Bakışta Özet

| Konu | Tek cümlelik özü |
|---|---|
| **SIEM** | SIM + SEM; ingestion → normalization → analiz. Değer üçüncü adımda |
| **SOC** | Operasyonu yürütür; Tier 1 triyaj, Tier 2 derin analiz + tuning, Tier 3 hunting |
| **MITRE ATT&CK** | 14 tactic'lik ortak dil; Defense Evasion 37 technique ile en geniş alan |
| **Elastic Stack** | Beats taşır, Logstash normalize eder, Elasticsearch saklar, Kibana gösterir |
| **KQL** | `field:value` + mantıksal operatörler; zor olan syntax değil, doğru field'ı seçmek |
| **ECS** | Farklı kaynakları aynı field adlarıyla korele etmeyi sağlayan ortak şema |
| **Use Case Development** | 9 aşamalı döngü; severity'yi belirleyen şey davranışın nadirliği |
| **Visualization** | Dört adım hep aynı; ayrışan tek şey hangi koşulu seçtiğin |
| **Alert Triaging** | 12 adım, dört faz: anla → değerlendir → aksiyon al → yönet |

---

## Kaynaklar

- HTB Academy — *Security Monitoring & SIEM Fundamentals* (CDSA path)
- MITRE ATT&CK — Enterprise Matrix
- Elastic — ECS, Winlogbeat ve Filebeat field referansları
- Microsoft — Windows Security Auditing event referansları (`4624`, `4625`, `4732`, `4733`)
- Gartner — *Enhance IT Security through Vulnerability Management* (2005)

---

<p align="center">
  <a href="../README.md">← Tüm modüller</a>
</p>
