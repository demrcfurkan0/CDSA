[← Tüm modüller](../README.md)

# 01 — Incident Handling Process

> HTB CDSA path'inin ilk modülü için tuttuğum **Incident Handling** çalışma notları.
> NIST SP 800-61 süreci, Cyber Kill Chain, MITRE ATT&CK ve Pyramid of Pain'in
> pratik bir case management platformu (TheHive) üzerinde nasıl birleştiği.

Notlar Türkçe yazıldı, teknik terimler bilinçli olarak İngilizce bırakıldı —
saha dili bu şekilde.

---

## İçindekiler

**Bölüm I — Temeller**
1. [Temel Kavramlar](#1-temel-kavramlar)
2. [NIST Incident Response Lifecycle](#2-nist-incident-response-lifecycle)
3. [Organizasyon ve Roller](#3-organizasyon-ve-roller)
4. [Gerçek Dünya Vakaları](#4-gerçek-dünya-vakaları--root-cause-odaklı)
5. [Raporlama Türleri](#5-raporlama-türleri)
6. [Referans Senaryo: Insight Nexus](#6-referans-senaryo-insight-nexus)

**Bölüm II — Saldırgan Perspektifi**

7. [Cyber Kill Chain](#7-cyber-kill-chain)
8. [MITRE ATT&CK](#8-mitre-attck)
9. [Pyramid of Pain](#9-pyramid-of-pain)
10. [TheHive — Case Management](#10-thehive--case-management)

**Bölüm III — Süreç Aşamaları**

11. [Süreç Mantığı](#11-süreç-mantığı)
12. [Preparation Stage](#12-preparation-stage)
13. [Detection & Analysis Stage](#13-detection--analysis-stage)
14. [Containment, Eradication & Recovery](#14-containment-eradication--recovery-stage)
15. [Post-Incident Activity](#15-post-incident-activity-stage)
16. [Tek Bakışta Özet](#16-tek-bakışta-özet)

---

# Bölüm I — Temeller

## 1. Temel Kavramlar

| Terim | Tanım | Örnek |
|---|---|---|
| **Event** | Sistem/ağda gerçekleşen herhangi bir aksiyon. Nötr. | Mail gönderimi, mouse click, firewall'ın bağlantıya izin vermesi |
| **Incident** | Negatif sonucu olan event. Kötü niyet şart değil. | System crash, doğal afet, power failure |
| **IT security incident** | Bir bilgisayar sistemine karşı, açık zarar verme niyetiyle yapılan event | Data theft, unauthorized access, malware/RAT kurulumu |
| **Incident handling** | Bu olayları yönetmek için tanımlanmış prosedürler bütünü | NIST SP 800-61 süreci |

**Kritik ayrım:** event → incident geçişi otomatik değil. Bir event'in incident olup
olmadığı ancak *initial investigation* sonrası netleşir. Ama bazı şüpheli event'ler,
aksi kanıtlanana kadar incident kabul edilir (*guilty until proven innocent*).

**Kapsam hatırlatması:** Incident handling sadece intrusion değil — malicious insider,
availability sorunları ve intellectual property kaybı da kapsam içinde.

---

## 2. NIST Incident Response Lifecycle

```
┌──────────────┐     ┌────────────────────┐     ┌──────────────────────────────┐     ┌────────────────────────┐
│ Preparation  │ ──► │ Detection & Analysis│ ──► │ Containment, Eradication,    │ ──► │ Post-Incident Activity │
│              │     │                     │     │ and Recovery                 │     │                        │
└──────▲───────┘     └─────────▲───────────┘     └──────────────┬───────────────┘     └───────────┬────────────┘
       │                       │                                │                                 │
       │                       └────────── yeni IOC ────────────┘                                 │
       └──────────────────── lessons learned / yeni detection rule ───────────────────────────────┘
```

Diyagramdaki oklar tek yönlü değil — modeldeki asıl fikir **feedback loop**:

- Containment sırasında yeni bir IOC bulursan → *Detection & Analysis*'e geri dönersin (scope büyür)
- *Post-Incident Activity* çıktısı → *Preparation*'ı besler (yeni detection rule, yeni playbook, yeni hardening)

Yani süreç lineer değil, **iteratif**.

---

## 3. Organizasyon ve Roller

| Konu | Detay |
|---|---|
| **Ekip adı** | Incident handling team = incident response team (aynı şey) |
| **Lider** | *Incident manager* — genelde SOC manager, CISO/CIO veya güvenilir 3rd-party vendor |
| **Yetkisi** | Diğer business unit'lere direktif verebilir; herhangi bir çalışandan zamanında aksiyon talep etme mandate'i vardır |
| **Rolü** | *Single point of communication* — tüm aktiviteleri ve tamamlanma durumunu takip eder |
| **Model seçimi** | In-house ekip veya third-party provider (sürekli / ihtiyaç anında) |
| **Prioritization** | Severity yüksek olan önce kaynak alır; düşük olanlar bile en azından initial investigation hak eder |
| **Referans doküman** | NIST *Computer Security Incident Handling Guide* (SP 800-61) |

---

## 4. Gerçek Dünya Vakaları — Root Cause Odaklı

| Kategori | Vaka | Root cause | Ders |
|---|---|---|---|
| Leaked credentials | **Colonial Pipeline** | Dark web'den sızmış parola + inactive VPN account, MFA yok | Kullanılmayan hesaplar ölü değil, saldırı yüzeyi |
| Default/weak creds | **Mirai Botnet** (2016) | IoT cihazlarda `admin/admin` | Fabrika defaultları = kitlesel DDoS |
| Default/weak creds | **LogicMonitor** (2023) | Vendor'ın müşteriye zayıf default parola vermesi | Vendor kaynaklı risk de senin incident'ın |
| Unpatched | **Equifax** (2017) | Apache Struts CVE-2017-5638, patch yayınlanmıştı | 143–147M kişi; patch gecikmesi |
| Unpatched | **WannaCry** (2017) | SMB EternalBlue, MS17-010 patch'i mevcuttu | 200K+ sistem, 150+ ülke; worm hızı |
| Insider threat | **Cash App / Block** (2021) | Eski çalışanın legitimate access'i + yetersiz monitoring | ~8.2M müşteri; offboarding kontrolü |
| Phishing | **US Interior Dept.** | Evil twin sahte Wi-Fi ile credential çalma | Wireless altyapı + zayıf authentication |
| Social engineering | **Twitter hijack** (2020) | Çalışanlar üzerinden admin tool erişimi | İç araçlar en değerli hedef |
| Supply chain | **SolarWinds Orion** (2020) | Build/release ortamına backdoor enjeksiyonu | Güvendiğin update kanalı = giriş kapısı |

> Vakaların büyük kısmının root cause'u temel hijyen: default credential, eksik patch,
> MFA yokluğu, offboarding eksikliği.

---

## 5. Raporlama Türleri

|  | **Incident-specific report** | **Global / annual report** |
|---|---|---|
| **Örnek** | *Confluence Exploit Leads to LockBit Ransomware* (The DFIR Report) | *Unit 42 Global Incident Response Report 2025* |
| **Kapsam** | Tek bir olay, tek bir outbreak | Yüzlerce olayın agregasyonu |
| **Yapı** | Kill Chain / MITRE ATT&CK sırasıyla: initial access → execution → persistence → … → impact | Trend, istatistik, sektörel pattern |
| **Amaç** | Forensic narrative + actionable finding | Emerging threat + üst düzey öneri |
| **Örnek veri** | — | 2024'te olayların %86'sı business disruption içerdi; bir kampanyada 230M+ unique target tarandı |

> Raporlama Kill Chain / ATT&CK sırasıyla yazılır — bu bir konvansiyon, keyfi değil.

---

## 6. Referans Senaryo: Insight Nexus

**Kurban:** Global market research firması; IT sektöründeki müşterilerin hassas rekabet
verisini tutuyor. Ortamda eş zamanlı **iki farklı threat group** var.

| # | Aşama | Aksiyon |
|---|---|---|
| 1 | **Initial access** | Product update sonrası ManageEngine ADManager Plus üzerinde `admin/admin` default parolası değiştirilmemiş, internete açık |
| 2 | **Discovery** | Başarılı login → recon, user ve machine mapping |
| 3 | **Persistence / PrivEsc** | Yeni privileged Active Directory hesapları oluşturma |
| 4 | **Lateral movement** | Yeni hesapla pivot; misconfiguration sonucu dışarı açık RDP servisi bulunması |
| 5 | **Impact** | GPO üzerinden MSI package ile birden fazla endpoint'e spyware deployment |

**Tespit zinciri:**
`endpoint/DC event logs → SIEM → TheHive (integration) → SOC analyst → alerts & cases`

---

# Bölüm II — Saldırgan Perspektifi

## 7. Cyber Kill Chain

```
  pre-compromise            compromise                    post-compromise
┌───────┬───────────┬─────────┐ ┌─────────┐ ┌─────────┬───────┬────────┐
│ Recon │ Weaponize │ Deliver │ │ Exploit │ │ Install │  C&C  │ Action │
└───▲───┴───────────┴─────────┘ └─────────┘ └────┬────┴───────┴────────┘
    └──────────────────── yeni hedef / yeni zafiyet ──┘
```

Adversary **lineer hareket etmez.** Installation'dan sonra mantıklı sonraki adım çoğu
zaman tekrar *Recon*'dur (yeni hedef, yeni zafiyet, daha derine). Aynı aşamalar defalarca
tekrarlanır.

**Savunma hedefi tek cümle:** saldırganı zincirde ilerlemeden, mümkün olan en erken
aşamada durdurmak.

### Aşama aşama

| # | Aşama | Saldırgan ne yapar | Ayırt edici nokta |
|---|---|---|---|
| 1 | **Recon** | Hedef seçimi + bilgi toplama | Active vs passive ayrımı |
| 2 | **Weaponize** | Malware'in exploit/payload içine gömülmesi | Hedefte kurban ortamı yok — saldırgan kendi tarafında çalışır |
| 3 | **Deliver** | Payload'ın kurbana ulaştırılması | Phishing attachment/link, sahte web sayfası, telefonla social engineering, USB drop |
| 4 | **Exploit** | Exploit veya payload'ın tetiklenmesi | Kod çalıştırma anı |
| 5 | **Install** | Initial stager'ın kurbanda çalışması, kalıcılık | Dropper / backdoor / rootkit |
| 6 | **C&C** | Uzaktan erişim kanalının kurulması | Modüler stager, "on-the-fly" script yükleme |
| 7 | **Action** | Asıl amaç | Data exfiltration, en yüksek yetki, ransomware |

### Active vs Passive Recon

| Active Recon | Passive Recon |
|---|---|
| Hedefi ve network scope'unu belirleme | Web kaynaklarından bilgi toplama |
| Open port tespiti | Job ads ve company partners (kullanılan teknolojiyi ifşa eder) |
| Port üzerindeki servisleri tespit | Social media: LinkedIn, Instagram, Facebook |
| Tüm network'ü map'leme | Her zaman tespitten kaçınma |
| **Hedefle temas var → log bırakır** | **Temas yok → hedef tarafında iz yok** |

> Passive recon'un gücü: iş ilanları antivirus, OS ve networking teknolojisi hakkında
> son derece spesifik bilgi verir. Saldırgan bunu *Weaponize* aşamasında EDR bypass için kullanır.

### Installation Teknikleri

| Teknik | Amaç | Tek cümlelik ayrım |
|---|---|---|
| **Dropper** | Malware'i sisteme kurup çalıştıran küçük kod parçası | Taşıyıcıdır, kendisi asıl malware değildir |
| **Backdoor** | Compromised sisteme sürekli erişim sağlar | Erişimin devamlılığı |
| **Rootkit** | Varlığını gizler, AV ve güvenlik araçlarından kaçar | Gizlilik odaklı |

İleri seviye gruplar ağda **birden fazla malware varyantı** bırakır — biri tespit edilip
contain edilse bile geri dönebilirler. Containment yaparken "tek IOC'yi temizledim, bitti"
tuzağı tam olarak budur.

### Sık Karıştırılanlar

- **Deliver ≠ Exploit.** Phishing maili inbox'a düştü → *Delivery*. Kullanıcı attachment'ı açtı → *Exploitation*.
- **Install ≠ C&C.** Install = stager makinede çalışıyor. C&C = uzaktan erişim kanalı kuruldu.

---

## 8. MITRE ATT&CK

| Katman | Tanım | Örnek |
|---|---|---|
| **Tactic** | Yüksek seviye adversary hedefi (matriste sütun) | Initial Access, Persistence, Privilege Escalation |
| **Technique** | Tactic'e ulaşmak için kullanılan somut yöntem | `T1105` Ingress Tool Transfer (wget, curl), `T1021` Remote Services (SSH, RDP, SMB) |
| **Sub-technique** | Technique'in belirli implementasyonu/hedefi | `T1003.001` LSASS Memory, `T1021.002` SMB/Windows Admin Shares |

Sub-technique'in değeri **hassasiyet**: "T1003 tespit ettik" yerine
"T1003.001 — LSASS memory dumping tespit ettik" diyebilmek. Bu; detection, attribution ve
reporting'i netleştirir.

**Enterprise Matrix kapsamı:** Windows, Linux, macOS, cloud, network, mobile — yani
sadece endpoint değil.

**Analist olarak ATT&CK üç amaçla kullanılır:**
1. Adversary niyetini ve muhtemel sonraki adımı hızlıca anlamak
2. High-value asset'i hedefleyen technique'lere göre alert prioritization yapmak
3. Kill chain'i kıracak mitigation/containment aksiyonunu seçmek

### Örnek ATT&CK Mapping — LockBit Vakası

Format şablonu olarak kullanılabilir:

| Tactic | Technique | ID | Açıklama |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | `T1190` | Confluence CVE exploit edildi |
| Execution | Command and Scripting Interpreter: PowerShell | `T1059.001` | Payload download için PowerShell |
| Persistence | Windows Service | `T1543.003` | Kalıcılık için Windows Service |
| Credential Access | LSASS Memory Dumping | `T1003.001` | Credential çıkarımı |
| Lateral Movement | Remote Desktop Protocol | `T1021.001` | RDP ile yanal hareket |
| Impact | Data Encrypted for Impact | `T1486` | LockBit ransomware |

> Kill Chain **kaba çerçeve**, ATT&CK **granüler matris**. İkisi rakip değil, birlikte kullanılır.

---

## 9. Pyramid of Pain

```
                    ▲  TTPs                    ← Tough
                   ╱ ╲  Tools                  ← Challenging
                  ╱   ╲  Network/Host Artifacts ← Annoying
                 ╱     ╲  Domain Names          ← Simple
                ╱       ╲  IP Addresses         ← Easy
               ╱_________╲  Hash Values         ← Trivial
```

Yukarı çıktıkça saldırganın taktiğini değiştirmesi zorlaşır — yani ona daha çok "acı"
verirsin, karşılığında daha kalıcı bir detection kurmuş olursun.

| Katman | Neden o kadar acı verir | ATT&CK karşılığı |
|---|---|---|
| **Hash values** | Tek byte değiştir, hash değişir | — |
| **IP addresses** | Malicious IP'yi block'larsan yeni C2 sunucusuna geçer, seni sadece hafifçe yavaşlatır | `T1071` Command and Control |
| **Domain names** | Yeni domain almak ucuz ve hızlı | — |
| **Network/host artifacts** | Registry key, mutex name, filename — değiştirmesi emek ister, daha dayanıklı indicator | `T1547.001` Registry Run Keys / Startup Folder |
| **Tools** | Araç değiştirmek yeniden geliştirme demek | — |
| **TTPs** | Saldırganı çalışma biçimini kökten değiştirmeye zorlar = maksimum acı | `T1059` PowerShell abuse, `T1055` Process Injection |

**Özet denklem:**
`Hash/IP detection` = kolay atlatılır — `Behavioral TTP detection` = zor atlatılır, yüksek
saldırgan maliyeti, olgun savunma.

> Pyramid of Pain, IOC-tabanlı savunmadan behavior-tabanlı savunmaya geçişin gerekçesidir.

---

## 10. TheHive — Case Management

| Konu | Detay |
|---|---|
| **Ne işe yarar** | Case management platformu; alert'leri işleyerek incident yönetir |
| **Temel yetenek** | Birden fazla ilgili alert'i tek case altında bağlama; tüm cihazlardan gelen alert'leri tek sayfada toplama |
| **ATT&CK entegrasyonu** | Tüm TTP'leri alert management sistemine import edebilir → alert'i tespit edilen attack pattern ile ilişkilendirir |

**Alert alanları:** `STATUS` (New), `SEVERITY`, `TITLE`, `# CASE`, `TYPE` (wazuh_alert),
`SOURCE` (wazuh), `REFERENCE`, `Observables`, `TTPs`, `ASSIGNEE`, tarihler
(O./C./U. = Occurred, Created, Updated).
Alert tag'leri örneği: `rule=92105`, `agent_name=SCDC01`, `agent_id=005`, `agent_ip=172.16.200.50`.

> **Dikkat:** Alert'lerde `TTPs = 0` gelir. Yani ATT&CK mapping otomatik değil —
> analist yapar. Otomasyon yazılacak en somut SOAR noktalarından biri burası.

**Analist iş akışı:**
`alert'i kendine assign et → case oluştur → üzerinde çalış → case'e detay ekle →
bulguları ve lessons'ı dokümante et → case'i kapat`

---

# Bölüm III — Süreç Aşamaları

## 11. Süreç Mantığı

> **Kritik cümle:** Incident Handling Process, Cyber Kill Chain ile bire bir eşleşmez.
> İkisi farklı perspektif — biri saldırganın, diğeri savunmanın yaşam döngüsü.

Süreç iki ana aktiviteye indirgenir: **investigating** ve **recovering**.
Investigation'ın ilk hedefi **patient zero** ve **incident timeline**.

### Zaman Dağılımı

| Aşama | Zaman payı | Not |
|---|---|---|
| **Preparation** | Yüksek | Incident handler'lar zamanlarının çoğunu ilk iki aşamada geçirir |
| **Detection & Analysis** | Yüksek | Kendini geliştirme + bir sonraki malicious event'i arama |
| Containment, Eradication, Recovery | Olay anında | — |
| Post-Incident Activity | Olay sonrası | — |

**Kritik detay:** bir olaya response verilirken bile ilk iki aşamada çalışan kaynak
bulunmalı. Yoksa preparation ve detection kabiliyeti kesintiye uğrar. Tüm ekip tek
incident'a dalmaz.

### Sürecin Üç Kuralı

| Kural | Açıklama | Gerekçe |
|---|---|---|
| **Döngüsel, lineer değil** | Yeni kanıt bulundukça sonraki adımlar değişir | Investigation canlı bir süreç |
| **Adım atlanmaz** | Bir adımı bitirmeden diğerine geçilmez | Eksik iş sonraki aşamayı bozar |
| **Kısmi aksiyon yasak** | 10 makine infected ise 5'ini contain edip eradication'a başlanmaz | Saldırgana fark edildiğini haber verirsin → öngörülemez sonuçlar |

Üçüncü kural sürecin en somut dersi: **containment eş zamanlı ve tam olmalı.** Yarım
containment; saldırganı panikletip destruction, hızlandırılmış exfiltration veya yeni
backdoor açmaya iter.

### Kapanış Çıktıları

1. **Report** — olayın sebebi (*cause*) ve maliyeti (*cost*)
2. **Lessons learned** — benzer olayların tekrarını önlemek için organizasyonun ne yapması gerektiği

### Sık Karıştırılanlar

- **"Patient zero"** = ilk kurban, en son bulduğun makine değil. Timeline'ın başlangıç noktası.
- Rapor sadece teknik değil — **cost** da içerir.
- "Process cyclic" ifadesi Kill Chain'in tekrar eden yapısıyla aynı şey değil: burada
  döngü *yeni kanıt geldikçe geri dönüş*, orada *saldırganın aşamaları tekrarlaması*.

---

## 12. Preparation Stage

Preparation'ın **iki ayrı hedefi** var:

1. **Incident handling kabiliyeti kurmak**
2. **Incident'ı önlemek** (protective measures)

> İkinci hedef IH ekibinin sorumluluğu **değildir**, ama o ekibin başarısı için temeldir.
> "Preparation'da hardening kim yapar?" sorusunun cevabı IH ekibi değil.

**Outsourcing notu:** IH ekibi dışarıdan alınabilir, ama temel kabiliyet ve anlayış her
hâlükârda in-house olmalı.

### 12.1 Policies & Documentation

| Kategori | İçerik |
|---|---|
| **İletişim** | IH ekibi üyelerinin iletişim bilgileri ve rolleri |
| **Dış iletişim** | Legal & compliance, management, IT support, communications/media relations, law enforcement, ISP, facility management, external IR team |
| **Prosedür** | Incident response policy, plan ve procedures |
| **Paylaşım** | Incident information sharing policy ve prosedürleri |
| **Referans durum** | Sistem ve network baseline'ları — golden image ve clean state ortamından alınmış |
| **Topoloji** | Network diagram'ları |
| **Envanter** | Organization-wide asset management database |
| **Yetki** | Excessive privilege'a sahip on-demand hesaplar |
| **Satın alma** | Belirli tutara kadar tam procurement süreci olmadan hızlı alım yetkisi |
| **Pratik** | Forensic / investigative cheat sheet'leri |

**On-demand privileged accounts — yaşam döngüsü:**

```
initial investigation'da incident doğrulanır
   → hesap enable edilir
   → incident biter
   → hesap disable edilir
   → zorunlu password reset
```

Business-critical sistemler için, o sistemi yönetebilecek yetkinlikteki kişiye özel
hesaplar da bu kapsamda.

**Hızlı satın alma:** incident sırasında $500'lık bir aracın onayını haftalarca beklemek
kabul edilemez.

**Compliance:** Müşteri verisi içeren bir data breach, GDPR kapsamında belirli bir süre
eşiği içinde law enforcement'a bildirilmek zorunda. Gereklilikler lokasyona/şubeye göre
değişir — doğru yaklaşım legal & compliance ekibiyle incident bazında ya da proaktif
olarak konuşmak.

### 12.2 Incident Sırasında Dokümantasyon

Hazır doküman bulundurmak kadar, olay devam ederken dokümante etmek de zorunlu.

| Alan | Neden |
|---|---|
| **Timestamp** | Timeline'ın omurgası |
| **Yapılan activity** | Ne denendi |
| **Result** | Sonuç ne oldu |
| **Kim yaptı** | Sorumluluk ve tekrarlanabilirlik |

Genel çerçeve: **who, what, when, where, why, how.** Incident son derece stresli; hızlı
hareket ederken not almak ilk unutulan şey oluyor.

### 12.3 Tools & Jump Bag

| Kategori | Araç / ekipman |
|---|---|
| **İş istasyonu** | Her ekip üyesi için ek laptop veya forensic workstation (malware test edileceği için antivirus kapalı; kuruma risk getirmeyecek şekilde yönetilir) |
| **Disk** | Digital forensic image acquisition & analysis araçları, write blocker, forensic imaging için hard disk |
| **Bellek** | Memory capture & analysis araçları |
| **Canlı sistem** | Live response capture & analysis araçları |
| **Log** | Log analysis araçları |
| **Network** | Network capture & analysis araçları, network kablosu ve switch |
| **Donanım** | Power cable, tornavida, cımbız ve donanım söküp onarma aletleri |
| **Tehdit verisi** | IOC creator + organizasyon genelinde IOC arama yeteneği |
| **Yasal** | Chain of custody formları |
| **Gizlilik** | Encryption software |
| **Takip** | Ticket tracking system |
| **Fiziksel** | Depolama ve inceleme için secure facility |
| **Bağımsızlık** | Kurum altyapısından bağımsız incident handling sistemi |

**Jump bag:** Araçların çoğu, alınıp hemen olay yerine götürülebilecek şekilde önceden
hazırlanmış çantada bulunur. Bu çanta yoksa araçları olay anında toplamak günler hatta
haftalar alabilir.

### 12.4 En Kritik Prensip — Assume Breach / Out-of-Band

| Varsayım | Sonuç |
|---|---|
| Tüm domain compromised | Dokümantasyon sistemi kurum altyapısından **tamamen bağımsız** ve güvenli olmalı |
| Tüm sistemler unavailable olabilir | Belgelere erişim kurumdan bağımsız olmalı |
| Adversary her şeyi kontrol ediyor ve okuyabiliyor | Incident iletişimi kurum kanallarından **yapılmaz** — e-mail dahil |

> Uygulamada en çok ihlal edilen kural: saldırganın domain admin olduğu bir ortamda
> "incident var" mailini Exchange üzerinden atmak, ona doğrudan haber vermektir.

### 12.5 Protective Measures

Sekiz önlem, iki gruba ayrılır:
**teknik kontroller** (bir kez kur, sürekli çalışsın) ve
**tekrarlayan aktiviteler** (süreklilik gerektirir, tek seferlik değil).

#### DMARC

| Konu | Detay |
|---|---|
| **Nedir** | Mevcut SPF ve DKIM üzerine kurulu, phishing'e karşı e-mail koruma mekanizması |
| **Mantığı** | Kendi organizasyonumuzdan geliyormuş gibi görünen mailleri reddetmek |
| **Tipik senaryo** | Saldırgan çalışan kılığında fatura ödeme talebi gönderir → mail alıcıya ulaşmadan reject edilir |
| **Maliyet** | Kolay ve ucuz |
| **Risk** | Kapsamlı test zorunlu — aksi halde legitimate mailleri geri getiremeyecek şekilde bloklarsın |

Bir seviye ileri: *email filtering rules* ile sahip olmadığımız domain'lerden gelip
DMARC'tan kalan maillere de koruma uygulanabilir — bazı e-mail sistemleri DMARC kontrolü
yapıp sonucu message header'a yazar.

> **Tipik false positive:** "on behalf of" gönderim yapan e-mail servisleri. Domain
> mismatch yüzünden DMARC'tan kalırlar ama meşrudurlar.

#### Endpoint Hardening & EDR

Endpoint'ler saldırıların giriş noktası. Baseline standartları: **CIS** ve **Microsoft baselines**.

| Aksiyon | Detay |
|---|---|
| **LLMNR/NetBIOS kapat** | Klasik credential relay/poisoning yolu |
| **LAPS uygula** | Normal kullanıcılardan admin yetkisini kaldır |
| **PowerShell** | Kapat veya `ConstrainedLanguage` mode'da yapılandır |
| **ASR rules** | Microsoft Defender kullanılıyorsa aç |
| **Whitelisting** | Neredeyse imkânsız ama en azından user-writable klasörlerden execution'ı blokla: `Downloads`, `Desktop`, `AppData` — payload'ların ilk düştüğü yerler |
| **Script tipleri** | `.hta`, `.vbs`, `.cmd`, `.bat`, `.js` ve benzerlerini blokla |
| **LOLBin'ler** | Whitelisting yaparken gözden kaçırma — initial access'te whitelisting bypass için gerçekten kullanılıyorlar |
| **Host-based firewall** | Minimum: workstation-to-workstation iletişimi engelle + LOLBin'lere giden outbound trafiği engelle |
| **EDR** | Ürün seçerken **AMSI entegrasyonu** olanı seç — obfuscated script'lere, çalışmadan önce içerik inceleme görünürlüğü verir |

#### Network Protection

| Kontrol | Detay |
|---|---|
| **Segmentation** | Breach'in tüm organizasyona yayılmasını engeller. Business-critical sistemler izole, bağlantılar sadece iş gereği kadar |
| **İnternet maruziyeti** | Internal kaynaklar doğrudan internete bakmaz — DMZ dışında |
| **IDS/IPS** | Asıl gücü SSL/TLS interception yapıldığında ortaya çıkar: trafiği **içeriğe** göre analiz eder, IP reputation'a göre değil |
| **Cihaz kontrolü** | Sadece onaylı cihazlar ağa girsin → 802.1x ile BYOD/malicious device riskini azalt |
| **Cloud karşılığı** | Azure / Microsoft Entra ID ortamında aynı etki **Conditional Access** ile: sadece company-managed cihazdan erişim |

#### Privileged Identity Management / MFA / Passwords

Privileged user credential çalmak, AD ortamlarında **en yaygın escalation yoludur.**

| Yaygın hata | Açıklama |
|---|---|
| Zayıf ama "complex" parola | `Password1!` — büyük/küçük harf, rakam, özel karakter var ama tahmin edilebilir ve saldırganın password list'lerinde mevcut |
| Paylaşılan parola | Admin hesabı ile normal kullanıcı hesabının aynı parolası — keylogging gibi birçok vektörle ele geçirilebilir |

**Çözüm:** passphrase. Örnek: `i LIK3 my coffeE warm` — hatırlaması kolay, uzun ve
karmaşık. İkinci bir dil biliniyorsa kelimeleri karıştırmak ek koruma sağlar.

**MFA:** en azından tüm uygulama ve cihazlardaki her türlü administrative access için zorunlu.

#### Vulnerability Scanning

- Sürekli tarama yap, en azından **High** ve **Critical** olanları remediate et
- Tarama otomatikleştirilebilir ama fix'ler genelde manuel emek ister
- Patch uygulanamıyorsa → o sistemleri mutlaka **segmente et**

#### User Awareness Training

- %100 başarı beklenmez ama başarılı compromise sayısını belirgin şekilde düşürdüğü biliniyor
- Periyodik "surprise" testing eğitimin parçası olmalı: aylık phishing mailleri, ofise bırakılan USB stick'ler

#### Active Directory Security Assessment

| Konu | Detay |
|---|---|
| **Yaklaşım** | Misconfiguration ve exposed critical vulnerability'leri bulmanın en iyi yolu, onlara saldırgan gözüyle bakmak |
| **Kim yapar** | Kendi ekibimiz; yetkinlik yoksa third party |
| **Hedef** | Bir endpoint compromise olduğunda saldırganın tek adımda yüksek yetkiye yükselememesi |
| **Detection bağlantısı** | Saldırgan ne kadar çok ek araç ve aktivite üretmek zorunda kalırsa, tespit olasılığı o kadar artar → low-hanging fruit'ları yok et |

#### Purple Team Exercises

| Konu | Detay |
|---|---|
| **Amaç** | Incident handler'ları eğitmek ve engaged tutmak — en iyi yer kurumun kendi ortamı |
| **Tanım** | Red team'in yaptığı, blue team'i aksiyonları/bulguları/görünürlük eksikleri hakkında sürekli veya sonradan bilgilendiren güvenlik değerlendirmesi |
| **Çift kazanç** | Kurumun zafiyetlerini bulur + blue team'in logging, monitoring, detection ve responsiveness kabiliyetini test eder |
| **Tespit edilmeyen tehdit** | İyileştirme fırsatı |
| **Tespit edilen tehdit** | Playbook'ları ve IH prosedürlerini test etme fırsatı |

### 12.6 Sık Karıştırılanlar

- Forensic workstation'da antivirus **bilerek** kapalı — malware orada test edilecek. Bu bir zafiyet değil, tasarım.
- Baseline, çalışan bir makineden değil, **golden image ve clean state** ortamından alınır.
- **Write blocker**, imaging sırasında kaynak diske yazmayı engeller; chain of custody ile birlikte delil bütünlüğünü sağlar. İkisi ayrı kalem, aynı amaç.
- "Excessive privilege accounts" hazırlığı least privilege ilkesine aykırı değildir — hesaplar normalde **disabled**.
- **Complex ≠ strong.** `Password1!` complexity policy'sini geçer ama zayıftır.
- **DMARC tek başına çalışmaz** — SPF ve DKIM'in üstüne kurulur.
- **802.1x** on-prem, **Conditional Access** cloud karşılığı. Aynı amaç, farklı ortam.
- Patch uygulanamıyorsa alternatif "görmezden gelmek" değil, **segmentation**.
- **Purple team ≠** red team + blue team'in ayrı ayrı çalışması. Fark: bilgi paylaşımının varlığı.

---

## 13. Detection & Analysis Stage

### 13.1 Tespit Katmanları

Ağı mantıksal olarak katmanlara böl: **perimeter → internal → endpoint → application.**
Amaç: saldırgan bir katmanı atlatsa bile diğerinde iz bırakır.

Detection'ı besleyen unsurlar: sensors, logs, eğitimli personel, bilgi paylaşımı,
context-based threat intelligence, mimari segmentasyon ve network'te net görünürlük.

### 13.2 Tespit Nereden Gelir

| Kaynak | Not |
|---|---|
| Çalışan anormal davranış fark eder | Awareness training'in karşılığı |
| Araç alert'i | EDR, IDS, Firewall, SIEM |
| Threat hunting | Proaktif arama, alert beklemeden |
| **Third-party notification** | Dışarıdan biri, compromise olduğumuzun izini bulduğunu bildirir |

> Sonuncusu en kötü senaryo: kendi ortamındaki ihlali başkasından öğrenmek.

### 13.3 Initial Investigation

**Neden önce bağlam?** Örnek: *"administrative account HH:MM:SS'te şu IP'ye bağlandı."*
O IP'nin hangi sistem olduğunu ve saatin hangi time zone olduğunu bilmeden yanlış sonuca
varmak çok kolay. Bu yüzden ekibi toplayıp kurum çapında IR başlatmadan önce initial
investigation yapılır.

| Soru | Detay |
|---|---|
| Ne zaman rapor edildi | Date/time + kim tespit etti / kim rapor etti |
| Nasıl tespit edildi | Detection kaynağı |
| Ne oldu | Phishing? System unavailability? |
| Etkilenen sistemler | Liste çıkar |
| Kim dokundu | Etkilenen sistemlere kim erişti, ne yaptı |
| Durum | Ongoing mu, yoksa şüpheli aktivite durdu mu |
| Sistem künyesi | Fiziksel konum, OS, IP ve hostname, system owner, sistemin amacı, mevcut durumu |
| Malware varsa | IP listesi, tespit tarih/saati, malware tipi, etkilenen sistemler, hash ve dosya kopyaları ile forensic bilgi |

> Amaç karar vermek: CEO'nun laptop'ı ile stajyerin makinesi compromise olduğunda
> alınacak aksiyon aynı değildir.

### 13.4 Incident Timeline

Yapı sabit:

| Date | Time of the event | Hostname | Event description | Data source |
|---|---|---|---|---|
| 09/09/2021 | 13:31 CET | SQLServer01 | Hacker tool 'Mimikatz' was detected | Antivirus Software |

| Özellik | Açıklama |
|---|---|
| **Sıralama** | Olayların gerçekleştiği zamana göre |
| **Keşif sırası** | Delilleri kronolojik sırayla bulmayacaksın — ama sıraladığında bağlam oluşur |
| **Ek fayda** | Yeni bulunan delilin bu incident'a ait olup olmadığını ayırt etmeyi sağlar |
| **Örnek** | "Initial payload" sandığın dosyanın başka bir cihazda iki hafta önce de bulunduğunun ortaya çıkması |
| **Odak** | Attacker behavior — saldırı ne zaman oldu, bağlantı ne zaman kuruldu, dosyalar ne zaman indirildi |
| **Zorunlu alan** | Aktivitenin nerede tespit edildiği ve ilişkili sistemler |

> `13:31 CET` — **time zone yazmak opsiyonel değil.** Farklı kaynaklardan gelen log'ları
> birleştirirken timeline'ı bozan tek numara budur.

### 13.5 Alert Anatomisi (Insight Nexus akışı)

| Severity | Alert | ATT&CK tag'leri |
|---|---|---|
| **M** | Possible suspicious access to Windows admin shares | — (`rule=92105`, `agent_name=SCDC01`, `agent_ip=172.16.200.50`) |
| **C** | Hacker tool Mimikatz was detected | `T1003.001`, Credential Dumping, `T1003` |
| **H** | Admin Login via ManageEngine Web Console | `T1078.001`, Valid Accounts, Initial Access |

Severity harfleri: **Critical > High > Medium > Low.**

*Admin Login via ManageEngine* = `T1078.001` (Valid Accounts / Default Accounts ailesi) ve
Initial Access — senaryodaki `admin/admin` girişinin log'daki karşılığı. Mimikatz alert'i
ise aynı zincirin **Credential Access** halkası.

### 13.6 Severity & Extent — Yedi Soru

| Soru | Ne ölçer |
|---|---|
| Exploitation impact nedir? | Etki büyüklüğü |
| Exploitation requirements nelerdir? | İstismarın zorluğu |
| Business-critical sistemler etkilenebilir mi? | İş sürekliliği |
| Önerilen remediation adımları var mı? | Çözülebilirlik |
| Kaç sistem etkilendi? | Yayılım |
| Exploit *in the wild* kullanılıyor mu? | Adversary sofistikasyonu |
| Exploit'in *worm-like* kabiliyeti var mı? | Adversary sofistikasyonu |

**Kural:** yüksek impact → hızlı müdahale; çok sayıda etkilenen sistem → escalation.

### 13.7 Confidentiality & Communication

| Prensip | Gerekçe |
|---|---|
| **Need-to-know esası** | Yasa veya yönetim kararı aksini söylemedikçe |
| Neden bu kadar katı | Adversary şirketin bir çalışanı olabilir |
| İletişim kimden çıkar | Breach durumunda iç/dış iletişimi **atanmış kişi**, legal department ile uyumlu şekilde yürütür |

### 13.8 Investigation Döngüsü

```
   ┌──────────────┐     ┌──────────────────────────┐     ┌─────────────────────┐
   │ IOC oluştur  │ ──► │ Etkilenen sistemleri     │ ──► │ Veri topla & analiz │
   │              │     │ tespit et / yeni lead    │     │                     │
   └──────▲───────┘     └──────────────────────────┘     └──────────┬──────────┘
          └──────────────────── yeni IOC ──────────────────────────┘
```

**"Neden sistemi baştan kurup unutmuyoruz?"** — Nasıl olduğunu bilmezsen aldığın remedial
adımlar saldırganın aynı yoldan geri dönmesini engellemez. Giriş yolunu, kullanılan
araçları ve etkilenen sistemleri tam bilirsen, o attack path'in tekrarlanamayacağı bir
remediation planlarsın.

**Lead disiplini:** Ekip sürekli yeni lead üretmeli, tek bir bulguya saplanmamalı.
Araştırmayı tek aktiviteye daraltmanın sonucu: sınırlı bulgu, erken varılmış sonuç, eksik
impact anlayışı.

### 13.9 IOC — Tanım ve Standartlar

| Konu | Detay |
|---|---|
| **Tanım** | Bir incident'ın gerçekleştiğine dair işaret; yapılandırılmış şekilde dokümante edilen compromise artifact'leri |
| **Örnekler** | IP adresleri, dosya hash değerleri, dosya adları |
| **OpenIOC** | IOC'leri standart biçimde dokümante etme ve paylaşma dili |
| **YARA** | Yaygın kullanılan diğer IOC standardı |
| **STIX** | CISA'nın IOC yayınlama formatı — open-source, machine-readable, JSON tabanlı; CTI paylaşımı için |
| **Araç** | Mandiant IOC Editor (ücretsiz) |
| **Kaynak** | Üçüncü taraflardan da alınabilir |

**STIX `file` objesinde neler bulunur:** MD5, SHA-1, SHA-256, SHA-512, **SSDEEP**
(fuzzy hash — benzer dosyaları yakalar, birebir değil), size, name ve
`windows-pebinary-ext` altında PE section'ları (`.text`, `.rsrc`, `.reloc`) ile her birinin
**entropy** değeri. Yüksek entropy = packed/encrypted içerik göstergesi.

### 13.10 Observables

| Alan | Değerler |
|---|---|
| **Type** | autonomous-system, domain, file, filename, fqdn, hash, hostname, ip |
| **Is IOC** | Toggle — observable ile IOC aynı şey değil, işaretlenmesi gerekir |
| **Has been sighted** | Ortamda görüldü mü |
| **Tags, Description** | Serbest alan |
| **Flags** | `TLP:AMBER`, `PAP:AMBER` |

Örnek observable yazımı: `manage[.]insightnexus[.]...` ve `103[.]112[.]60[.]117` —
defanged yazım (`[.]`) kazara tıklanmayı önler.

> **Her observable bir IOC değildir.** Observable = gözlemlenen veri.
> IOC = compromise göstergesi olarak doğrulanmış olan. `Is IOC` toggle'ı bu kararı temsil eder.

### 13.11 Credential Caching — Pratik Uyarı

Investigation sırasında yüksek yetkili hesabının credential'ının compromised sistemde
cache'lenmesini engellemelisin. Aksi halde saldırgana kendi elinle domain admin hash'i
vermiş olursun.

| Durum | Cache'lenir mi |
|---|---|
| WinRM ile bağlantı | Hayır |
| Logon type 3 (Network Logon) | Genelde hayır |
| **PsExec — explicit credential ile** | **Evet**, uzak makinede cache'lenir |
| PsExec — credential'sız, mevcut oturum üzerinden | Hayır |

> Aynı araç, kullanım şekline göre farklı iz bırakıyor. Klasik "know your tools" örneği.

Ölçekli IOC araması için Windows ortamında yaygın yaklaşım: **WMI** veya **PowerShell**.

### 13.12 Yeni Lead ve Etkilenen Sistem Tespiti

| Durum | Aksiyon |
|---|---|
| IOC hit'leri geldi | Aynı compromise izini taşıyan başka sistemler ortaya çıkar |
| Hit ilgisiz olabilir | IOC çok generic olabilir → false positive'leri ayıkla |
| Çok fazla hit var | Önceliklendir — ideal olarak forensic analiz sonrası yeni lead verebilecek olanlar |

### 13.13 Veri Toplama ve Analiz

| Yöntem | Ne zaman | Risk |
|---|---|---|
| **Live response** | En yaygın yaklaşım; sistem çalışırken önceden tanımlı, artifact açısından zengin veri seti toplanır | — |
| **Shutdown + analiz** | Bazı durumlarda | Artifact'lerin çoğu sadece RAM'de yaşar, kapatınca kaybolur |

**Altın kural:** sistemle minimum etkileşim — delil ve artifact'i değiştirmemek için.

| Analiz | Not |
|---|---|
| Malware analysis ve disk forensics | En yaygın inceleme türleri |
| Memory forensics | Giderek yaygınlaşıyor, advanced attack'lerde son derece ilgili |
| **Süre** | Analiz, incident'ın en çok zaman alan kısmıdır |
| **Çıktı** | Yeni doğrulanmış lead'ler timeline'a eklenir; timeline sürekli güncellenir |

**Chain of custody** veri toplama boyunca takip edilmeli — saldırgana karşı yasal işlem
yapılacaksa incelenen verinin mahkemede kabul edilebilir (*court-admissible*) olması buna
bağlı.

### 13.14 AI in Threat Detection

Geleneksel akışta analist log, alert ve raporu elle inceler — saatler ya da günler alır.
AI bu analizin çoğunu otomatikleştirir; geçmiş incident'lardan öğrenip behavioral
anomaly'leri insandan hızlı tespit eder.

**Örnek: Elastic Security "Attack Discovery"** — generative AI ile binlerce detection'dan
gelen event'i analiz eder, ilişkili alert'leri tek bir *attack story* altında kümeler.

**BPFDoor vakası:**

| Bileşen | İçerik |
|---|---|
| **Başlık / durum** | *BPFDoor Linux backdoor deployment* — Open, 4 alert |
| **Summary** | `SRVNIX05` host'unda, `root` kullanıcısı backdoor'u extract etti, kopyaladı, çalıştırdı |
| **Details** | `unzip` ile açma → `bash` ile `/dev/shm/kdmtmpflush`'a kopyalama → `chmod 755` → çalıştırma → orijinali `rm -f` ile silme |
| **Tespit** | `Linux.Trojan.BPFDoor` |
| **Justification for separation** | Tüm alert'ler aynı host ve kullanıcıya bağlı, extraction'dan execution'a net bir sıra var; başka host/kampanya ile bağlantı yok |
| **Attack Chain** | Initial Access, Execution, Persistence, **Defense Evasion** |

`/dev/shm` (RAM disk) kullanımı ve orijinal dosyanın silinmesi klasik **Defense Evasion**.
AI'ın yaptığı iş: dört ayrı alert'i tek anlatıya çevirip ATT&CK mapping'ini vermek.

**AI'ın IR use case'leri:** automated triage & alert prioritization, incident correlation &
timeline reconstruction, automated response playbooks, post-incident analysis & learning.

### 13.15 Sık Karıştırılanlar

- **Timeline ≠ kronolojik keşif.** Delili rastgele sırayla bulursun, sıralayarak anlamlandırırsın.
- **Data source sütunu opsiyonel değil** — hangi kanıtın nereden geldiğini kaybedersen timeline savunulamaz hale gelir.
- **Initial investigation ≠ full investigation.** Amaç karar verebilmek için yeterli bağlam, tüm cevaplar değil.
- Breach'i müşteriye/üçüncü tarafa incident handler bildirmez, **atanmış kişi** bildirir.
- **Generic IOC = false positive kaynağı.** Hit sayısının çokluğu başarı değil, filtreleme ihtiyacıdır.
- **Shutdown kararı "temkinli davranmak" değildir** — delil imha edebilir. Memory'yi öncelikle düşün.
- **SSDEEP** diğer hash'lerden farklı: fuzzy hash, benzerlik ölçer.
- **Chain of custody** sadece yasal süreç için değil, veri toplama boyunca tutulur — sonradan geriye dönük yazılamaz.
- AI çıktısı **Justification** bölümü okunmadan kabul edilmez.

---

## 14. Containment, Eradication & Recovery Stage

```
Investigation complete → Containment strategy → Evidence gathering (preserve evidence)
   → Identify the attacking host → Eradication & Recovery → Bring systems back to normal operation
```

### 14.1 Short-term vs Long-term Containment

|  | **Short-term** | **Long-term** |
|---|---|---|
| **Amaç** | Yayılmayı durdurmak, zaman kazanmak | Kalıcı aksiyon ve değişiklikler |
| **Sisteme etki** | Minimal footprint — sistem mümkün olduğunca değiştirilmemiş kalır | Sistem üzerinde kalıcı değişiklik |
| **Yan kazanç** | Sistem bozulmadığı için forensic image alıp delil koruma fırsatı (= containment'ın *backup substage*'i) | — |
| **Sonrası** | Somut bir remediation stratejisi geliştirme süresi | Business ve stakeholder'lar sürekli bilgilendirilir |

### 14.2 Değişmez Kural — Eş Zamanlılık

Containment aksiyonları **tüm sistemlerde koordineli ve eş zamanlı** yürütülmeli. Aksi
halde saldırgana peşinde olduğunu bildirirsin; o da ortamda kalıcı olmak için technique ve
tool'larını değiştirir.

Short-term containment bir sistemi kapatmayı gerektiriyorsa, bu business'a bildirilmeli ve
uygun izinler alınmalı.

### 14.3 Eradication

| Konu | Detay |
|---|---|
| **Ne zaman** | Incident contain edildikten sonra |
| **Amaç** | Hem root cause'u hem geriye kalanları yok etmek; adversary'nin sistemlerden ve network'ten çıktığından emin olmak |
| **Aktiviteler** | Tespit edilen malware'in kaldırılması, bazı sistemlerin rebuild edilmesi, bazılarının backup'tan restore edilmesi |
| **Genişleme** | Containment'ta acilen gerekmemiş ek patch'ler burada uygulanır |
| **Hardening** | Ek sistem hardening — bazen sadece etkilenen sistemde değil, network genelinde |

> Bir sistemin patch'lenmiş olması incident'ın bittiği anlamına **gelmez.** Eradication,
> recovery ve post-incident faaliyetleri hâlâ beklemededir.

### 14.4 Recovery

| Adım | Detay |
|---|---|
| **Doğrulama** | Business, sistemin beklendiği gibi çalıştığını ve tüm gerekli veriyi içerdiğini doğrular |
| **Üretime alma** | Doğrulama tamamlanınca sistemler production'a alınır |
| **Sonrası** | Tüm restore edilen sistemler yoğun logging ve monitoring altına alınır |
| **Gerekçe** | Compromised sistemler, adversary kısa sürede ortama geri dönerse tekrar hedef olma eğilimindedir |

**İzlenecek tipik şüpheli olaylar:**

| Olay | Neye işaret eder |
|---|---|
| Unusual logons | Daha önce o makinede hiç login olmamış kullanıcı veya service account |
| Unusual processes | Beklenmeyen çalışan süreçler |
| Registry değişiklikleri | Malware'in tipik olarak değiştirdiği konumlarda |

**Recovery'nin süresi:** büyük incident'larda aylar sürebilir ve genelde fazlı yürütülür.

| Faz | Odak |
|---|---|
| Erken fazlar | Genel güvenliği artırmak — quick win'ler ve low-hanging fruit'ların elenmesi |
| Geç fazlar | Kalıcı, uzun vadeli değişiklikler |

### 14.5 Sık Karıştırılanlar

- **Sistem kapatma** her iki listede de geçer — short-term'de acil izolasyon amaçlı (izin gerekir), long-term'de kalıcı aksiyon olarak. Bağlam belirler.
- **Patch ≠ incident bitti.**
- **C2 DNS sinkhole** short-term'dir — kalıcı bir değişiklik değil, zaman kazandırır.
- Eradication ile containment arasındaki sınır keskin değil: containment'ta atlanmış patch'ler eradication'da uygulanır. Ama **sıra değişmez** — önce contain, sonra eradicate.
- Recovery'de "sistem çalışıyor" yetmez; **verinin eksiksizliği** de doğrulanır.
- Recovery'de üretime alma kararını **business** verir, IH ekibi değil.

---

## 15. Post-Incident Activity Stage

Amaç iki kelimeyle: **dokümante et ve kabiliyeti geliştir.**

Bu aşama, olaya dönüp bakma fırsatıdır — ne oldu, biz ne yaptık, yaptıklarımız nasıl sonuç
verdi. Bilgi en iyi şekilde, olaya dahil olan **tüm stakeholder'ların** katıldığı bir
toplantıda toplanır ve analiz edilir.
**Zamanlaması:** incident report finalize edildikten sonra, olaydan birkaç gün içinde.

### 15.1 Final Report'un Cevaplaması Gereken Sorular

| Soru | Odak |
|---|---|
| Ne oldu ve ne zaman oldu? | Olayın kendisi |
| Ekip; plan, playbook, policy ve procedure'lere göre nasıl performans gösterdi? | Ekip değerlendirmesi |
| Business gerekli bilgiyi sağladı mı, hızlı yanıt verdi mi? Ne geliştirilebilir? | Organizasyonel destek |
| Contain ve eradicate için hangi aksiyonlar uygulandı? | Teknik icraat |
| Benzer olayları önlemek için hangi preventive measure'lar konmalı? | Gelecek koruma |
| Benzerlerini tespit ve analiz için hangi tool ve resource gerekli? | Kabiliyet eksiği |

> Soruların sadece ikisi teknik. Rapor bir olay anlatısı değil, bir **öz değerlendirme belgesi**.

### 15.2 Raporun Dört Çıktısı

| Çıktı | Detay |
|---|---|
| **Ölçülebilir sonuç** | Kaç incident handle edildi, ekip incident başına ne kadar zaman harcıyor, handling sırasında hangi aksiyonlar yapıldı |
| **Referans** | Benzer nitelikteki gelecek olaylar için başvuru kaynağı |
| **Hukuki** | Yasal işlem durumunda mahkemede kullanılır + incident'ın maliyet ve etkisini belirleme kaynağı |
| **Eğitim** | Yeni ekip üyelerine, deneyimli meslektaşların olayı nasıl ele aldığını göstererek eğitim |

### 15.3 Yeniden Değerlendirilecekler

Bu aşamada sadece dokümantasyon ve süreç tarafına odaklanma:

| Boyut | Soru |
|---|---|
| Plans, playbooks, policies, procedures | Güncelleme gerekiyor mu |
| Tools | Elimizdeki araçlar yeterli miydi |
| Training | Ekibin eğitimi yeterli miydi |
| Readiness | Hazırlık seviyesi neredeydi |
| Team structure | Ekip yapısının kendisi doğru mu |

> Son üçü çoğu ekibin atladığı kısım — rapor yazılır, playbook güncellenir, ama ekip yapısı
> ve hazırlık hiç sorgulanmaz.

### 15.4 Aşamanın Akışı

```
Incident resolved → Post-incident review → Lessons learned meeting → Root cause analysis
   → Update policies and playbooks → Enhance detection and monitoring rules
   → Knowledge sharing and awareness → Report to management and close case
```

**Enhance detection & monitoring rules** adımı, döngüyü *Preparation*'a geri bağlayan
halkadır. Post-incident'ın çıktısı yeni detection rule ise, bir sonraki benzer olay daha
erken yakalanır.

### 15.5 Sık Karıştırılanlar

- Lessons learned toplantısı **"birkaç gün içinde"** yapılır — hemen değil (rapor bitmeli), haftalar sonra da değil (detaylar unutulur).
- Rapor **maliyeti de içerir**; cost ve impact belirleme kaynağıdır.
- **Root cause analysis** bu aşamada geçer ama eradication'daki *root cause eliminasyonu* ile karıştırma: orada kökü yok edersin, burada neden oluştuğunu analiz edersin.
- Post-incident activity incident'ın "formalite" kısmı değil — **döngünün kapanma noktası.** Atlanırsa aynı incident tekrar eder.

---

## 16. Tek Bakışta Özet

| Aşama | Tek cümlelik özü | Zaman payı |
|---|---|---|
| **Preparation** | Kabiliyet kur + önle | Yüksek |
| **Detection & Analysis** | Tespit et, bağlam kur, timeline'ı büyüt | Yüksek |
| **Containment, Eradication, Recovery** | Eş zamanlı durdur, kökü kaz, doğrulayarak geri getir | Olay anında |
| **Post-Incident Activity** | Raporla, öğren, Preparation'ı güncelle | Olay sonrası |

---

## Kaynaklar

- NIST SP 800-61 — *Computer Security Incident Handling Guide*
- Lockheed Martin — *Cyber Kill Chain*
- MITRE ATT&CK — Enterprise Matrix
- David J. Bianco — *The Pyramid of Pain*
- OASIS — *STIX* / CISA IOC yayınları
- The DFIR Report — *Confluence Exploit Leads to LockBit Ransomware*
- Unit 42 — *Global Incident Response Report 2025*
- HTB Academy — *Incident Handling Process* (CDSA path)

---

<p align="center">
  <a href="../README.md">← Tüm modüller</a>
</p>
