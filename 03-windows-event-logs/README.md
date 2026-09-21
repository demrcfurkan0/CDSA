[← Tüm modüller](../README.md)

# 03 — Windows Event Logs & Finding Evil

> HTB CDSA path'inin üçüncü modülü için tuttuğum çalışma notları.
> Windows event'inin anatomisi ve Logon ID korelasyonu, kritik System/Security event ID'leri,
> Sysmon ile üç saldırının tespiti, ETW mimarisi ve Sysmon'un yanıltıldığı senaryolar,
> Get-WinEvent ile komut satırından kitlesel log analizi.

Notlar Türkçe yazıldı, teknik terimler bilinçli olarak İngilizce bırakıldı.

---

## İçindekiler

**Bölüm I — Windows Event Logs**

1. [Temeller ve Event Anatomisi](#1-temeller-ve-event-anatomisi)
2. [Korelasyonun Anahtarı: Logon ID](#2-korelasyonun-anahtarı-logon-id)
3. [Kritik Event ID'ler](#3-kritik-event-idler)

**Bölüm II — Sysmon**

4. [Sysmon Nedir](#4-sysmon-nedir)
5. [Üç Detection Senaryosu](#5-üç-detection-senaryosu)

**Bölüm III — ETW**

6. [Event Tracing for Windows](#6-event-tracing-for-windows-etw)
7. [Tapping Into ETW — Sysmon'un Kör Noktaları](#7-tapping-into-etw--sysmonun-kör-noktaları)

**Bölüm IV — Araç**

8. [Get-WinEvent](#8-get-winevent)
9. [Tek Bakışta Özet](#9-tek-bakışta-özet)

---

# Bölüm I — Windows Event Logs

## 1. Temeller ve Event Anatomisi

| Konu | Detay |
|---|---|
| **Ne saklar** | Sistemin kendisi, uygulamalar, ETW provider'lar, servisler ve diğer bileşenlerden gelen log'lar |
| **Varsayılan log'lar** | Application, Security, Setup, System, Forwarded Events |
| **Forwarded Events** | Diğer makinelerden iletilen log verisi — merkezi görünüm isteyen sistem yöneticileri için |
| **Erişim** | Event Viewer uygulaması veya programatik olarak Windows Event Log API |
| **Saved Logs** | Daha önce kaydedilmiş `.evtx` dosyaları açılabilir |

> Event Viewer'ı **administrative user** olarak açmak gerekir — aksi halde Security log'una
> erişilemez.

### 1.1 Bir Event'in 11 Bileşeni

| Alan | Ne içerir |
|---|---|
| **Log Name** | Event log'un adı (Application, System, Security…) |
| **Source** | Event'i loglayan yazılım |
| **Event ID** | Benzersiz tanımlayıcı |
| **Task Category** | Event'in amacını/kullanımını anlamaya yarayan değer veya ad |
| **Level** | Severity: Information, Warning, Error, Critical, Verbose |
| **Keywords** | Diğer sınıflandırmaların ötesinde flag'ler — Security log'unda "Audit Success" / "Audit Failure" |
| **User** | Event gerçekleştiğinde logon olmuş kullanıcı hesabı |
| **OpCode** | Event'in raporladığı spesifik operasyon |
| **Logged** | Loglanma tarih ve saati |
| **Computer** | Event'in gerçekleştiği bilgisayarın adı |
| **XML Data** | Yukarıdakilerin tamamı + ek event verisi XML formatında |

**Keywords** alanı filtrelemede özellikle değerli: Security log'unda `Audit Failure` ile
filtrelemek başarısız işlemleri tek hamlede ayıklar.

Details sekmesinde iki görünüm var: **Friendly View** ve **XML View**. XML View'dan
`EventRecordID`, `ProcessID`, `ThreadID`, `Channel`, `SystemTime` gibi ek alanlara ulaşılır.

---

## 2. Korelasyonun Anahtarı: Logon ID

`4624` event'inde iki kritik alan var:

| Alan | Ne sağlar |
|---|---|
| **Logon ID** | Aynı Logon ID'yi paylaşan diğer event'lerle korelasyon kurmanı sağlar |
| **Logon Type** | Logon'un türü (Type 5 = Service, yani SYSTEM yeni bir servis başlatmış) |

> Hangi servis olduğu `4624`'te **yazmaz**. Bunu bulmak için Logon ID üzerinden korelasyon
> yapmak gerekir. Modülün öğrettiği asıl refleks bu.

### 2.1 XML Query ile Korelasyon

Yol: *Filter Current Log → XML → Edit query manually*

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[EventData[Data[@Name='SubjectLogonId']='0x3E7']]
    </Select>
  </Query>
</QueryList>
```

Bu sorgu, `SubjectLogonId` alanı `0x3E7` olan tüm event'leri getirir.

> **İpucu:** sorguyu yazmakta zorlanırsan otomatik filtreleri kullan, sonra XML
> gösterimine bakarak nasıl karşılık bulduğunu gör.

### 2.2 Ortaya Çıkan Anlatı

Aynı Logon ID ile filtreleyince olaylar bir hikâye anlatmaya başlıyor.

**Event 4907 — audit policy change**
*"This event generates when the SACL of an object (for example, a registry key or file) was changed."*

| Kavram | Açıklama |
|---|---|
| **SACL** | System Access Control List — yöneticilerin güvenli nesnelere yapılan erişim denemelerini loglamasını sağlar |
| **ACE** | Access Control Entry — SACL içindeki her girdi, hangi erişim denemelerinin security event log'una kayıt üreteceğini belirler |
| **Kapsam** | ACE'ler başarısız, başarılı veya her iki erişim denemesi için audit kaydı üretebilir |

| Alan | Örnek değer | Yorum |
|---|---|---|
| `ProcessName` | `SetupHost.exe` | Kurulum süreci gibi görünüyor — ama malware meşru isimlerle maskelenebilir |
| `ObjectName` | `…bootmgfw.efi` | Etkilenen nesne: boot manager |
| `OldSd` / `NewSd` | `S:ARAI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)` | Eski ve yeni security descriptor (SDDL syntax) — değişikliği tespit etmek için karşılaştırılır |

**Event 4672 — special logon**

Başarılı logon'da kullanıcıya verilen token permission'larını gösterir:
`SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeSecurityPrivilege`,
`SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`,
`SeRestorePrivilege`, **`SeDebugPrivilege`**, `SeAuditPrivilege`,
`SeSystemEnvironmentPrivilege`, `SeImpersonatePrivilege`,
`SeDelegateSessionUserImpersonatePrivilege`.

> **`SeDebugPrivilege`**: kullanıcının kendisine ait olmayan belleğe müdahale edebilmesi
> demek. **Credential dumping'in ön koşulu.**

---

## 3. Kritik Event ID'ler

### 3.1 System Log

| Event ID | Anlamı | Neden önemli |
|---|---|---|
| `1074` | System shutdown/restart | Beklenmedik kapanma/yeniden başlatma → malware veya yetkisiz erişim işareti |
| `6005` | Event log service started | Sistem boot'unun işareti; araştırma için başlangıç noktası |
| `6006` | Event log service stopped | Anormal görülmesi, illegal aktiviteyi örtmek için kasıtlı servis kesintisi olabilir |
| `6013` | Windows uptime | Günde bir kez, saniye cinsinden. Beklenenden kısa uptime → yeniden başlatma |
| `7040` | Service startup type değişikliği | Manual ↔ automatic geçişi. Kritik bir servisin tipi değiştiyse tampering işareti |

### 3.2 Security Log — Logon ve Kimlik Doğrulama

| Event ID | Anlamı | Tehdit sinyali |
|---|---|---|
| `4624` | Successful logon | Normal davranışı belirlemek için temel. Tuhaf saatlerde/yerlerden logon şüpheli |
| `4625` | Failed logon | Çok sayıda → brute force |
| `4648` | Explicit credential ile logon denemesi | Anomali → lateral movement |
| `4672` | Special privileges assigned to a new logon | Super user yetkisiyle logon — kötüye kullanım takibi |
| `4771` | Kerberos pre-authentication failed | `4625`'in Kerberos karşılığı. Olağandışı sayıda → Kerberos brute force |
| `4776` | DC, hesap credential'ını doğrulamaya çalıştı | Birden çok başarısızlık → brute force |

### 3.3 Security Log — Kalıcılık (Scheduled Task)

| Event ID | Anlamı |
|---|---|
| `4698` | Scheduled task created — saldırganların klasik persistence yöntemi |
| `4700` / `4701` | Scheduled task enabled / disabled |
| `4702` | Scheduled task updated |

### 3.4 Security Log — İz Gizleme ve Politika

| Event ID | Anlamı | Neden kritik |
|---|---|---|
| `1102` | The audit log was cleared | Genelde intrusion kanıtını silme girişimi |
| `4719` | System audit policy changed | Auditing'i kapatmak veya neyin loglandığını değiştirmek → iz örtme |
| `4738` | User account changed | Yetki, grup üyeliği, hesap ayarları → account takeover veya insider threat |
| `4656` | A handle to an object was requested | Hassas kaynaklara erişim denemesi tespiti |

### 3.5 Microsoft Defender

| Event ID | Anlamı |
|---|---|
| `1116` | Malware tespit edildi — ani artış → hedefli saldırı veya yaygın enfeksiyon |
| `1118` | Remediation başladı |
| `1119` | Remediation başarılı |
| `1120` | Remediation başarısız — acil ele alınmalı |
| `5001` | Real-time protection konfigürasyonu değişti — yetkisiz değişiklik = Defender'ı devre dışı bırakma girişimi |

### 3.6 Ağ ve Servis

| Event ID | Anlamı |
|---|---|
| `5140` | Network share object accessed — yetkisiz share erişimi tespiti |
| `5142` | Network share object added — exfiltration veya malware yayma aracı olabilir |
| `5145` | Share erişimi için yetki kontrolü yapıldı — sık tekrar → share haritalama girişimi |
| `5157` | Windows Filtering Platform bağlantıyı engelledi — malicious trafik tespiti |
| `7045` | A service was installed — bilinmeyen servislerin aniden belirmesi = malware kurulumu |

### 3.7 Kapanış İlkesi

Tehdit tespitinin anahtarı, ortamında **"normal"in ne olduğunu bilmek**. Bir ortamda tehdit
sayılan anomali, başka ortamda normal olabilir. Bu yüzden:

1. Monitoring ve alerting'i kendi ortamına göre **tune et** → false positive azalır
2. **Merkezi log yönetimi** şart — gerçek zamanlı toplama, parse ve alert
3. Log'ları **düzenli gözden geçir**
4. Bu log'ları diğer sistem ve güvenlik log'larıyla **korele et**

### 3.8 Key Takeaways

1. Varsayılan beş log: Application, Security, Setup, System, Forwarded Events.
2. Event'in 11 bileşeni var; **Keywords** filtrelemede, **XML Data** derin analizde kilit rol oynar.
3. **Logon ID**, event'leri birbirine bağlayan korelasyon anahtarıdır.
4. XPath/XML query ile Event Viewer'da alan bazlı filtreleme yapılabilir.
5. `4907` SACL değişikliği = auditing'e dokunulmuş demektir.
6. `4672`'deki `SeDebugPrivilege` credential dumping kapısıdır.
7. `1102` (audit log cleared) ve `4719` (audit policy changed) **iz gizleme ikilisidir**.
8. Detection, ortamın baseline'ı bilinmeden çalışmaz.

### 3.9 Sık Karıştırılanlar

- **`6005` ≠ sistem açıldı, `6006` ≠ sistem kapandı.** İkisi Event Log Service'in başlama/durma kaydı. Genelde boot/shutdown ile örtüşür ama aynı şey değildir — bu fark saldırganın servisi kasıtlı durdurduğu senaryoyu ortaya çıkarır.
- **`4625` NTLM/local, `4771` Kerberos tarafı.** Bir brute force saldırısında hangisinin göründüğü, saldırganın hangi protokolü kullandığını söyler.
- **`SetupHost.exe` gibi meşru görünen process adları maskelenmiş olabilir.** İsim değil, yol ve davranış doğrulanmalı.
- **Logon Type:** 5 = Service, 2 = Interactive, 3 = Network, 10 = RemoteInteractive (RDP). Type'ı okumadan `4624`'ü yorumlama.
- **`1102` tek başına en yüksek öncelikli event'lerden biri.** Audit log'u temizlemenin meşru bir günlük sebebi yoktur.

---

# Bölüm II — Sysmon

## 4. Sysmon Nedir

**System Monitor** — sistem reboot'ları boyunca resident kalan bir Windows service + device
driver. Sistem aktivitesini Windows event log'a yazar.

| Bileşen | İşlevi |
|---|---|
| Windows service | Sistem aktivitesini izler |
| Device driver | Aktivite verisini yakalamaya yardım eder |
| Event log | Yakalanan veriyi gösterir |

**Asıl değeri:** Security Event log'da tipik olarak görünmeyen bilgileri loglar — process
creation, network connection, file creation time değişikliği ve daha fazlası.

Konfigürasyon XML tabanlı. Process adı, IP vb. attribute'lara göre event include/exclude
edilir. Popüler config'ler: **SwiftOnSecurity/sysmon-config** ve **olafhartong/sysmon-modular**.

```powershell
# Kurulum
sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n

# Config yükleme
sysmon.exe -c filename.xml
```

**Log konumu:** Applications and Services → Microsoft → Windows → Sysmon.
Linux için Sysmon da mevcut.

### 4.1 Bu Bölümün Event ID'leri

| Event ID | Anlamı | Hangi saldırı |
|---|---|---|
| `1` | Process Creation | (genel) |
| `3` | Network Connection | (genel) |
| `7` | Image/Module Load | DLL hijacking, unmanaged injection |
| `10` | ProcessAccess | Credential dumping |

---

## 5. Üç Detection Senaryosu

### 5.1 DLL Hijacking (Event ID 7)

Config ayarı ters mantıklı ve kritik:

| Ayar | Sonuç |
|---|---|
| `<ImageLoad onmatch="include">` + kural yok | **Hiçbir şey loglanmaz** |
| `<ImageLoad onmatch="exclude">` + kural yok | **Her şey loglanır** |

DLL hijack yakalamak için `include` → `exclude` yapılır, böylece hiçbir image load
dışlanmaz.

> Sysmon'un genel mantığı: `onmatch="include"` = "sadece eşleşenleri logla",
> `onmatch="exclude"` = "eşleşenler hariç hepsini logla". Kural boşken ikisi zıt sonuç verir.

**Saldırı:** `calc.exe` + `WININET.dll`. Reflective DLL, `WININET.dll` olarak yeniden
adlandırılıp `calc.exe` ile birlikte yazılabilir bir dizine (Desktop) taşınır. `calc.exe`
çalıştırılınca hesap makinesi yerine MessageBox çıkar.

| Alan | Meşru load | Hijack |
|---|---|---|
| `Image` | `C:\Windows\System32\calc.exe` | `C:\Users\Waldo\Desktop\calc.exe` |
| `ImageLoaded` | `C:\Windows\System32\wininet.dll` | `C:\Users\Waldo\Desktop\WININET.dll` |
| `Signed` | `true` (Microsoft) | `false` |

**Üç IOC**

| IOC | Mantık |
|---|---|
| `calc.exe` writable dizinde | Orijinali System32/SysWOW64'te olmalı; başka yerde = IOC |
| `WININET.dll` System32 dışında, parent `calc.exe` | `calc.exe` için DLL adı değişmez, saldırgan kaçamaz → kesin hijack |
| DLL unsigned | Orijinal Microsoft-signed, enjekte edilen unsigned |

> **Nüans:** `WININET.dll`'nin System32 dışında yüklenmesine her durumda alarm vermek riskli
> — bazı uygulamalar stabilite için kendi DLL versiyonlarını paketler. Ama `calc.exe`
> özelinde emin olabilirsin, çünkü DLL adı sabit.

### 5.2 Unmanaged PowerShell / C# Injection (Event ID 7)

**Temel kavram:** C# "managed" bir dildir — çalışması için backend runtime gerekir: **CLR**
(Common Language Runtime). Managed kod doğrudan assembly olarak çalışmaz, bytecode'a
derlenir, runtime işler.

**Tespit mantığı:** C# çalıştıran her process `clr.dll` ve `clrjit.dll`'yi yükler. Bu
DLL'ler normalde bunlara ihtiyaç duymayan bir process'te görünüyorsa → `execute-assembly`
veya unmanaged PowerShell injection işareti.

**Araç:** Process Hacker. Managed process'ler yeşil renkte gösterilir
("Process is managed (.NET)").

```powershell
Invoke-PSInject -ProcId [spoolsv.exe PID] -PoshCode "..."
```

Sonuç: `spoolsv.exe` unmanaged'dan managed'a geçer. Process Hacker'da yeşile döner, Modules
sekmesinde `clr.dll` görünür. Sysmon Event ID 7 de doğrular: `spoolsv.exe` → `clr.dll` load,
Microsoft .NET Runtime, User `NT AUTHORITY\SYSTEM`.

> **Anahtar:** `spoolsv.exe` (Print Spooler) normalde .NET yüklemez. `clr.dll`'in orada
> olması tek başına şüphe sebebi.

### 5.3 Credential Dumping (Event ID 10)

**Saldırı:** Mimikatz, `sekurlsa::logonpasswords` → LSASS'a erişerek NTLM hash veya plaintext
parola çıkarır. LSASS credential yönetiminden sorumlu, bu yüzden credential dumping
araçlarının birincil hedefi.

**Ön koşul:** Mimikatz'ın `privilege::debug` ile `SeDebugPrivilege` talep etmesi — bir önceki
bölümdeki `4672` special logon ile bağlantısı burada.

**Tespit:** DLL load değil, **ProcessAccess (Event ID 10)**.

| Alan | Değer | Neden şüpheli |
|---|---|---|
| `SourceImage` | `C:\Users\waldo\Downloads\AgentEXE.exe` | Downloads'tan rastgele bir dosya |
| `TargetImage` | `C:\Windows\system32\lsass.exe` | LSASS hedefleniyor |
| `SourceUser` | `DESKTOP-R4PEEIF\waldo` | ↓ |
| `TargetUser` | `NT AUTHORITY\SYSTEM` | Source ≠ Target — normal dışı |
| `GrantedAccess` | `0x1010` | LSASS'a talep edilen erişim hakkı |
| `CallTrace` | `…ntdll.dll…KERNELBASE.dll…UNKNOWN(…)` | **UNKNOWN modül → shellcode işareti** |

**Üç IOC**

| IOC | Mantık |
|---|---|
| Rastgele klasörden (Downloads) rastgele dosya LSASS'a erişiyor | Anormal davranış |
| `SourceUser` ≠ `TargetUser` (waldo vs SYSTEM) | Yetki sınırı aşılıyor |
| `SeDebugPrivilege` talep edilmiş | Debugging için, ama credential dump'ın ön koşulu |

> Bazı meşru process'ler de LSASS'a erişir — authentication süreçleri, AV, EDR. Tek başına
> LSASS erişimi alarm değil; **kim, nereden, hangi CallTrace ile** sorularıyla birlikte
> değerlendirilir.

### 5.4 Üç Detection Yan Yana

|  | **DLL Hijacking** | **Unmanaged Injection** | **Credential Dumping** |
|---|---|---|---|
| **Sysmon Event** | 7 (Image Load) | 7 (Image Load) | 10 (ProcessAccess) |
| **Aranan** | System32 dışı unsigned DLL | Beklenmeyen process'te `clr.dll` | LSASS'a şüpheli erişim |
| **Anahtar IOC** | Unsigned + writable path | Unmanaged → managed geçiş | Source ≠ Target + UNKNOWN CallTrace |
| **ATT&CK** | Hijack Execution Flow | Process Injection | `T1003.001` LSASS Memory |
| **Ek araç** | — | Process Hacker | — |

### 5.5 Key Takeaways

1. Sysmon, Security log'da görünmeyen telemetriyi (image load, process access, network) sağlar.
2. Config'de **`include`** (sadece eşleşen) ile **`exclude`** (eşleşen hariç hepsi) zıt anlam taşır.
3. Event ID 7 hem DLL hijack hem unmanaged injection için kullanılır — fark aranan DLL'de.
4. DLL hijack'in üç IOC'si: yanlış path, unsigned, sabit DLL adı.
5. `clr.dll` + `clrjit.dll`, normalde .NET yüklemeyen bir process'te = injection işareti.
6. Event ID 10 LSASS erişimini yakalar; credential dumping'in ana detection'ı.
7. LSASS'a meşru erişim de var — bağlam (source, user farkı, CallTrace) belirleyici.

### 5.6 Sık Karıştırılanlar

- **`include` boşken hiçbir şey loglamaz.** Sezgiye ters. DLL hijack yakalamak için `exclude`'a çevrilir.
- **`Signed: true` tek başına güven vermez** — Microsoft-signed bir binary (`calc.exe`) hijack aracı olabilir. Bakılan şey DLL'in imzası ve path'i.
- **Event ID 7 (Image Load) ≠ Event ID 10 (ProcessAccess).** DLL load ≠ process access.
- **`clr.dll` birçok meşru .NET uygulamasında normaldir.** Şüphe, onu taşımaması gereken process'te (spoolsv) görülmesinden doğar.
- **`GrantedAccess: 0x1010` ve CallTrace'te UNKNOWN modül güçlü sinyaldir** — meşru araçların CallTrace'i genelde bilinen modüllerden oluşur.
- **`AgentEXE.exe` gibi isimler jenerik;** asıl IOC isim değil, path (Downloads) + davranış (LSASS erişimi).

---

# Bölüm III — ETW

## 6. Event Tracing for Windows (ETW)

Microsoft'un tanımıyla: OS tarafından sağlanan, genel amaçlı, yüksek hızlı bir **tracing
tesisi**. Kernel'de uygulanan bir buffering ve logging mekanizması kullanır; hem user-mode
uygulamalar hem kernel-mode device driver'lar tarafından üretilen event'leri izler.

**Neden değerli:** geleneksel log verisinin ötesine geçer — system call, process
oluşturma/sonlandırma, network aktivitesi, dosya ve registry değişiklikleri. Hafif ve düşük
performans etkili, real-time monitoring için ideal.

### 6.1 Mimari — Publish-Subscribe

```
┌────────────┐   enable/disable   ┌───────────┐   write   ┌──────────┐
│ Controller │───────────────────►│ Providers │──────────►│ Sessions │
│ (logman)   │                    └───────────┘           └────┬─────┘
└────────────┘                                                 │ buffer
                                                               ▼
                                  ┌───────────┐          ┌───────────┐
                                  │ Channels  │─────────►│ Consumers │──► .ETL
                                  └───────────┘ subscribe└───────────┘
```

| Bileşen | Rolü |
|---|---|
| **Controller** | Tüm ETW operasyonlarını kontrol eder: trace session başlatma/durdurma, provider enable/disable. Örnek araç: `logman.exe` |
| **Providers** | Event üretir ve ETW session'larına yazar |
| **Sessions** | Provider'lara subscribe olur, event'leri buffer'da toplar |
| **Consumers** | İlgilendikleri event'lere subscribe olur; varsayılan olarak `.ETL` dosyasına yönlendirilir |
| **Channels** | Event'leri özellik ve önemine göre organize eden mantıksal container'lar |
| **ETL files** | Event Trace Log — diske kalıcı yazım; offline analiz, arşivleme, forensic |

### 6.2 Dört Provider Tipi

| Tip | Açılım / temel | Kullanım |
|---|---|---|
| **MOF Providers** | Managed Object Format | Önceden tanımlı MOF şemasına göre event; esnek, yaygın |
| **WPP Providers** | Windows Software Trace Preprocessor | Kaynak koddaki makro/annotation ile; low-level kernel-mode tracing/debugging |
| **Manifest-based Providers** | XML manifest dosyası | Daha modern; esnek, yönetimi kolay, dinamik event |
| **TraceLogging Providers** | TraceLogging API | En basit ve verimli; minimal kod |

**Kritik notlar**

- ETW hem kernel mode hem user mode provider destekler.
- Bazı provider'lar çok yüksek hacimde event üretir → sistemi boğmamak için **varsayılan olarak kapalı**, sadece bir tracing session talep edince aktif olur.
- Custom provider ile genişletilebilir.
- **Sadece `Channel` property'si olan provider event'leri event log tarafından tüketilebilir.**

### 6.3 Logman ile Etkileşim

| Komut | Ne yapar |
|---|---|
| `logman.exe query -ets` | Aktif Event Tracing Session'ları listeler (system-wide) |
| `logman.exe query "EventLog-System" -ets` | Belirli session'ın detayı: name, max log size, log location, provider'lar |
| `logman.exe query providers` | Sistemdeki tüm provider'ları GUID'leriyle listeler |
| `logman.exe query providers \| findstr "Winlogon"` | Provider'ları filtreler |
| `logman.exe query providers Microsoft-Windows-Winlogon` | Bir provider'ın keyword'lerini, event level'larını ve onu kullanan PID'leri gösterir |

> **`-ets` parametresi hayati.** Onsuz Logman, Event Tracing Session'ı tanımaz.

| Alan | Anlamı |
|---|---|
| **Name / Provider GUID** | Provider'ın benzersiz tanımlayıcısı |
| **Level** | Event seviyesi filtresi: warning, informational, critical veya all |
| **Keywords Any** | Provider'ın ürettiği event türüne göre filtre |

Windows 10'da **1000'den fazla** yerleşik provider var. Üçüncü taraf yazılımlar da kendi
provider'larını ekler (özellikle kernel-mode).

**GUI alternatifleri:** Performance Monitor (çalışan trace session'ları görselleştirir,
"User Defined" ile yeni session), EtwExplorer (provider metadata'sı).

### 6.4 Faydalı Provider'lar — Saldırı Tipine Göre

| Provider | Ne tespit eder |
|---|---|
| **Kernel-Process** | Process injection, process hollowing, APT taktikleri |
| **Kernel-File** | Yetkisiz dosya erişimi, kritik sistem dosyası değişikliği, exfiltration/ransomware |
| **Kernel-Network** | Data exfiltration, yetkisiz bağlantı, C2 iletişimi |
| **SMBClient / SMBServer** | Anormal SMB trafiği → lateral movement, exfiltration |
| **DotNETRuntime** | .NET anomalileri, malicious assembly loading |
| **OpenSSH** | SSH bağlantı denemeleri, başarılı/başarısız auth, brute force |
| **VPN-Client** | Yetkisiz/şüpheli VPN bağlantıları |
| **PowerShell** | Şüpheli PowerShell kullanımı, script block logging |
| **Kernel-Registry** | Registry değişiklikleri → persistence, malware kurulumu |
| **CodeIntegrity** | Unsigned/malicious driver yükleme denemeleri |
| **Antimalware-Service** | Devre dışı bırakılan servis, config değişikliği, evasion |
| **WinRM** | Yetkisiz remote management → lateral movement, remote execution |
| **TerminalServices-LocalSessionManager** | Yetkisiz/şüpheli RDP aktivitesi |
| **Security-Mitigations** | Güvenlik mitigation'larını bypass denemeleri |
| **DNS-Client** | DNS tunneling, anormal DNS istekleri (C2) |
| **Antimalware-Protection** | AV koruma mekanizmalarında devre dışı bırakma/evasion |

### 6.5 Restricted Providers

Bazı ETW provider'ları "restricted" — sadece gerekli izinlere sahip process'ler erişebilir.

| Konu | Detay |
|---|---|
| **Örnek** | `Microsoft-Windows-Threat-Intelligence` — DFIR'da çok değerli |
| **Erişim şartı** | PPL (Protected Process Light) hakkı |
| **PPL nasıl alınır** | AV vendor'ı Microsoft'a başvurur, kimliğini kanıtlar, yasal doküman imzalar, ELAM driver uygular, test suite'ten geçirir, özel Authenticode imzası alır |
| **Sağladığı** | Sofistike saldırılara dair granüler veri, forensic delil, real-time tehdit tespiti |

### 6.6 ETW vs Sysmon

|  | **Sysmon** | **ETW** |
|---|---|---|
| **Kapsam** | Belirli event tipleri (process, network, image load…) | 1000+ provider, çok daha geniş telemetri |
| **Kurulum** | Ayrı kurulum + config | OS'e gömülü, hep orada |
| **Erişim kolaylığı** | Event Viewer'da hazır | Session/provider yönetimi gerektirir |
| **Zayıflık** | Belirli event'leri yakalayamaz | Karmaşıklık, hacim |

### 6.7 Key Takeaways

1. ETW, OS'e gömülü, kernel-tabanlı, yüksek hızlı tracing tesisi. User + kernel mode.
2. Mimari publish-subscribe: **Controller** yönetir, **Provider** üretir, **Session** toplar, **Consumer/ETL** tüketir.
3. Dört provider tipi: MOF, WPP, Manifest-based, TraceLogging.
4. `logman.exe` ana araç; `-ets` parametresi session sorgusu için zorunlu.
5. Sadece `Channel` property'li provider event'leri event log'dan tüketilebilir.
6. Threat-Intelligence provider restricted — PPL gerektirir.
7. ETW, Sysmon'un kaçırdığı event'leri yakalar — daha geniş ama daha karmaşık.

### 6.8 Sık Karıştırılanlar

- **`-ets` olmadan `logman query` Event Tracing Session'ı görmez.** En sık yapılan hata.
- **Provider'ların çoğu varsayılan kapalı.** "Provider var" demek "loglanıyor" demek değil; bir session onu enable etmeli.
- **Sysmon zaten ETW üzerine kuruludur** — Sysmon bir provider gibi düşünülebilir. ETW daha alt katman.
- **Threat-Intelligence provider'ına erişim kolay değil (PPL)**, ama workaround'lar var — saldırgan da bu provider'ı kör etmeye çalışabilir.
- **`Get-WinEvent` ve Message Analyzer consumer tarafı araçlarıdır**, controller değil. Controller `logman`.

---

## 7. Tapping Into ETW — Sysmon'un Kör Noktaları

### 7.1 Detection 1 — Strange Parent-Child Relationships

**Temel fikir:** Windows'ta bazı process'ler asla başkalarını spawn etmez. `calc.exe` →
`cmd.exe` normal bir ortamda görülmez. Bu ilişkileri bilmek anomali tespitinin temeli.
(Referans: Samir Bousseaden'in parent-child mind map'i.)

Örnek anomali: `spoolsv.exe` normalde `conhost` oluşturur; onun yerine `whoami.exe`
oluşturuyorsa → şüphe.

**Saldırı: Parent PID Spoofing** (psgetsystem projesi)

```powershell
[MyProcess]::CreateProcessFromParent([spoolsv.exe PID],"C:\Windows\System32\cmd.exe","")
```

Sysmon Event 1, spoof yüzünden `spoolsv.exe`'yi `cmd.exe`'nin parent'ı olarak gösterir —
ama aslında `powershell.exe` oluşturdu. Sysmon `ParentProcessId` alanına güveniyor, o alan
da spoof edilmiş.

**ETW ile veri toplama — SilkETW**

```powershell
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\windows\temp\etw.json
```

`etw.json` (Kernel-Process provider'ından) `powershell.exe`'nin `cmd.exe`'yi oluşturan
gerçek process olduğunu gösterir.

> SilkETW event log'ları, **SilkService** aracılığıyla Windows Event Viewer'a ingest edilebilir.

> **Ders:** Sysmon'un `ParentProcessId` alanı manipüle edilebilir. ETW Kernel-Process
> provider'ı process oluşturmayı **kernel seviyesinde** gördüğü için spoof'a karşı dayanıklı.

### 7.2 Detection 2 — Malicious .NET Assembly Loading

**İki saldırı stratejisinin evrimi**

| Strateji | Açılım | Mantık | Zayıflık |
|---|---|---|---|
| **LotL** | Living off the Land | Sistemde var olan meşru araçları (PowerShell) kullanmak | Savunma buna karşı gelişti |
| **BYOL** | Bring Your Own Land (Mandiant terimi) | Kendi .NET assembly'lerini memory'de çalıştırmak | ETW ile yakalanabilir |

**BYOL neden etkili**

| Sebep | Açıklama |
|---|---|
| .NET her Windows'ta var | Varsayılan yüklü |
| Managed nature | CLR memory yönetimini üstlenir, garbage collection |
| **In-memory execution** | Executable/DLL diske yazılmadan çalışır → minimal artifact, disk-tabanlı detection'ı bypass |
| Zengin kütüphaneler | HTTP, crypto, named pipe (IPC) — sofistike saldırı için hazır toolkit |

En güçlü örnek: CobaltStrike'ın `execute-assembly` komutu.

**Tespit yaklaşımı**

Unmanaged PowerShell injection'da olduğu gibi .NET-ilişkili DLL yüklenmesine bakılır — bu
sefer **`clr.dll` ve `mscoree.dll`**. Sysmon Event ID 7 ile yakalanır.

```powershell
.\Seatbelt.exe TokenPrivileges
```

Sysmon Event ID 7, `Seatbelt.exe`'nin `clr.dll` ve `mscoree.dll` yüklediğini loglar.
**Ama Sysmon'un sınırı burada:**

| Sysmon Event 7 verir | Sysmon Event 7 vermez |
|---|---|
| Hangi DLL yüklendi | Yüklenen assembly'nin içeriği |
| Process ID, path, signature | Çalıştırılan method adları |

Yani "`clr.dll` yüklendi" dersin ama "Seatbelt'in `TokenPrivileges` fonksiyonu çalıştı"
diyemezsin.

**ETW ile derinlik — DotNETRuntime provider**

```powershell
SilkETW.exe -t user -pn Microsoft-Windows-DotNETRuntime -uk 0x2038 -ot file -p C:\windows\temp\etw.json
```

`etw.json`, yüklenen assembly hakkında **method adları dahil** zengin bilgi içerir —
örnekte `LookupPrivilegeName`, `TOKEN_INFORMATION_CLASS` gibi Seatbelt'in iç metotları.

**`-uk 0x2038` keyword filtresi — dört keyword'ün birleşimi**

| Keyword | Ne yakalar |
|---|---|
| **JitKeyword** | Just-In-Time compilation event'leri — runtime'da derlenen metotlar, execution flow |
| **InteropKeyword** | Managed kod ↔ unmanaged kod etkileşimi — native API çağrıları |
| **LoaderKeyword** | Assembly loading süreci — hangi .NET assembly'leri yükleniyor |
| **NGenKeyword** | Native Image Generator — precompiled .NET assembly'ler; JIT-tabanlı detection'ı atlatma senaryosu |

> Bu, tüm DotNETRuntime event'lerini değil, **seçili bir alt kümeyi** yakalar. Tüm
> provider'ı açmak sistemi event'le boğar.

### 7.3 İki Detection Yan Yana

|  | **Parent-child spoofing** | **.NET assembly loading** |
|---|---|---|
| **Saldırı** | Parent PID Spoofing (psgetsystem) | BYOL / `execute-assembly` (Seatbelt) |
| **Sysmon ne der** | Yanlış parent (spoolsv) | DLL yüklendi ama içerik yok |
| **Sysmon'un sorunu** | Alan **manipüle edilebilir** | **Yeterince granüler değil** |
| **ETW provider** | Kernel-Process | DotNETRuntime |
| **ETW ne ekler** | Gerçek parent (powershell) | Method adları, assembly içeriği |
| **Araç** | SilkETW | SilkETW (`-uk 0x2038`) |

> İki senaryo Sysmon'un iki farklı zayıflığını gösteriyor: birinde **yanıltılıyor**,
> diğerinde **yetersiz kalıyor**. ETW ikisini de kapatıyor.

### 7.4 Key Takeaways

1. Parent PID Spoofing, Sysmon'un `ParentProcessId` alanını yanıltır; ETW Kernel-Process gerçeği gösterir.
2. SilkETW ETW verisini toplayan araç; `-pn` provider, `-uk` keyword filtresi, `-ot file -p` çıktı.
3. **LotL → BYOL evrimi**: var olan araçtan, memory'de çalışan kendi .NET assembly'sine geçiş.
4. BYOL'un gücü **in-memory execution** — diske yazmadan, disk-tabanlı detection'ı atlar.
5. .NET assembly loading, `clr.dll` + `mscoree.dll` yükü ile Sysmon Event 7'de görünür.
6. Sysmon "hangi DLL" der, ETW DotNETRuntime **"hangi method"** der.
7. `-uk 0x2038` = JIT + Interop + Loader + NGen keyword'leri.

### 7.5 Sık Karıştırılanlar

- **Sysmon'un parent process bilgisi güvenilir değildir** — spoof edilebilir. Bir alarm "spoolsv → cmd" gösteriyorsa, gerçek parent ETW ile doğrulanmalı.
- **İki detection da Event ID 7 kullanıyor ama farklı amaçla.** Burada `clr.dll` + `mscoree.dll` ikilisi anahtar (önceki bölümde `clr.dll` + `clrjit.dll` idi — farkı not et).
- **NGenKeyword özellikle önemli:** precompiled assembly JIT event üretmez, sadece JIT'e bakan bir detection bunu kaçırır. Saldırganın kaçış yolu.
- **SilkETW tüm provider'ı açarsa event patlaması olur** — `-uk` ile keyword filtresi şart.
- **`mscoree.dll` .NET'in giriş noktasıdır;** meşru .NET uygulamalarında da yüklenir. Şüphe, onu taşımaması gereken process'te görülmesinden doğar.

---

# Bölüm IV — Araç

## 8. Get-WinEvent

Büyük kurumlarda günde milyonlarca log üretilir; Event Viewer'da tek tek bakmak imkânsız.
`Get-WinEvent`, classic Windows log'larını (System, Application), Windows Event Log
teknolojisi log'larını ve **ETW log'larını** kitlesel sorgulamayı sağlar.

### 8.1 Keşif Komutları

| Komut | Ne yapar |
|---|---|
| `Get-WinEvent -ListLog *` | Tüm log'ları listeler: LogName, RecordCount, IsClassicLog, IsEnabled, LogMode, LogType |
| `Get-WinEvent -ListProvider *` | Tüm provider'ları ve bağlı oldukları log'ları (LogLinks) listeler |

| Alan | Anlamı |
|---|---|
| `IsClassicLog` | `.evt` (classic) mi `.evtx` (yeni) mi |
| `LogMode` | Circular, Retain veya AutoBackup |
| `LogType` | Administrative, Analytical, Debug, Operational |

### 8.2 Temel Çekme Komutları

```powershell
# System log'undan ilk 50 event
Get-WinEvent -LogName 'System' -MaxEvents 50

# Belirli log'dan 30 event
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -MaxEvents 30

# En eski 30 event (kronolojik başa göre)
Get-WinEvent -LogName 'System' -Oldest -MaxEvents 30

# Exported .evtx dosyasından okuma
Get-WinEvent -Path 'C:\...\file.evtx' -MaxEvents 5

# Tipik pipeline
Get-WinEvent -LogName 'System' -MaxEvents 50 |
  Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message |
  Format-Table -AutoSize
```

### 8.3 Filtreleme — Üç Yöntem

```
FilterHashtable  ──►  FilterXPath / FilterXml  ──►  Property + Where-Object
   temel/hızlı          granüler/iç alanlar            esnek/script
   ────────────────────── güç ve karmaşıklık artıyor ──────────────────────►
```

**Yöntem 1 — FilterHashtable** (en çok kullanılan)

```powershell
# Temel
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1,3}

# Exported dosya
Get-WinEvent -FilterHashtable @{Path='...file.evtx'; ID=1,3}

# Tarih aralığı
Get-WinEvent -FilterHashtable @{LogName='...'; ID=1,3; StartTime=$startDate; EndTime=$endDate}
```

> Tarih aralığı **start dahil, end hariç**. 28 Mayıs–2 Haziran istiyorsan `EndTime`'ı
> 3 Haziran vermen gerekir.

> **Anahtar not:** Sysmon ID 1 (Process Create) + ID 3 (Network Connection) kısa sürede
> birlikte görünüyorsa → process'in C2 sunucusuyla konuşuyor olma ihtimali. İkisini birlikte
> sorgulamanın asıl sebebi bu.

**Yöntem 2 — FilterXPath / FilterXml** (granüler)

`FilterHashtable` sadece üst seviye alanlarla (LogName, ID, zaman) filtreler. Ama
`DestinationIp`, `Image`, `CommandLine` gibi alanlar event'in **EventData** kısmının
içindedir. Bunlara ulaşmak için XPath/XML gerekir.

```powershell
# Belirli IP'ye bağlantı
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' `
  -FilterXPath "*[System[EventID=3] and EventData[Data[@Name='DestinationIp']='52.113.194.132']]"
```

```xml
<!-- clr.dll / mscoree.dll yükü — .NET assembly detection -->
<Select Path="Microsoft-Windows-Sysmon/Operational">
  *[System[(EventID=7)]] and *[EventData[Data='mscoree.dll']] or *[EventData[Data='clr.dll']]
</Select>
```

Bu, ETW bölümündeki Seatbelt / BYOL detection'ının `Get-WinEvent` versiyonu — aynı mantık,
farklı araç.

**Yöntem 3 — Property value + Where-Object** (en esnek)

`Select-Object -Property *` ile event'in tüm özelliklerini görürsün, sonra `Where-Object`
ile script mantığıyla filtrelersin. Sysmon Event ID 1'de index'ler sabittir:

| Index | Alan |
|---|---|
| `Properties[10]` | CommandLine |
| `Properties[21]` | ParentCommandLine |

```powershell
# Encoded PowerShell tespiti
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} |
  Where-Object {$_.Properties[21].Value -like "*-enc*"} |
  Format-List
```

`-enc` (EncodedCommand), PowerShell'de kötü niyetli script'i obfuscate etmenin klasik yolu.
Çıktıda base64 encoded command'lar görünür — Ansible'ın meşru kullanımı da olabilir, ama
saldırgan da aynısını yapar.

> `Properties[N]` index'leri event tipine göre değişir. Doğru index'i bulmak için önce Event
> Viewer'da event'in XML View'ına bakıp `<Data Name="…">` sırasını sayarsın (0'dan başlar).

### 8.4 XML'i Keşfetme

"`Event.EventData.Data`'yı nereden bildik?" sorusunun cevabı: **Windows XML EventLog (EVTX)**
formatı. Herhangi bir event'in *Details → XML View*'ına bakarak `<Data Name="Image">`,
`<Data Name="DestinationIp">` gibi alan adlarını görürsün. **Filtreleme yazmadan önce
yapılacak ilk şey bu.**

```powershell
# XML parse ile IP araştırma (ProcessGuid korelasyonu için)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} |
  ForEach-Object {
    $xml = [xml]$_.ToXml()
    # SourceIP, DestinationIP, ProcessGuid, ProcessId çıkar
  } |
  Where-Object {$_.DestinationIP -eq "52.113.194.132"}
```

Çıktıdaki `ProcessGuid`, bağlantıyı yapan process'i geriye izlemeni sağlar — process tree'yi
kurar, malicious executable'ı bulur. **Logon ID korelasyonunun network tarafındaki karşılığı.**

### 8.5 Key Takeaways

1. `Get-WinEvent` classic, modern ve ETW log'larını tek araçla sorgular.
2. Keşif: `-ListLog *` (log'lar), `-ListProvider *` (kaynaklar).
3. Üç filtre: **FilterHashtable** (temel/hızlı), **FilterXPath/Xml** (granüler/iç alanlar), **Property + Where-Object** (esnek/script).
4. `.evtx` dosyaları `-Path` ile okunur — offline analiz için.
5. FilterHashtable tarih aralığı **end hariç** — bir gün fazla ver.
6. Sysmon ID 1 + ID 3 kısa sürede = olası C2.
7. `Properties[21]` = ParentCommandLine; `-enc` araması obfuscated PowerShell yakalar.
8. Filtre yazmadan önce event'in XML View'ına bakıp alan adlarını öğren.

### 8.6 Sık Karıştırılanlar

- **FilterHashtable üst seviye alanlarla sınırlı.** `DestinationIp`, `CommandLine` gibi EventData alanları için XPath/XML şart. Bu ayrımı bilmemek en sık takılma noktası.
- **`Properties[N]` index'leri event tipine özgü.** ID 1 için 21 = ParentCommandLine, başka event'te farklı. XML'den doğrula.
- **Tarih aralığında end date exclusive** — 2 Haziran'ı dahil etmek için 3 Haziran yaz.
- **`-enc` araması false positive üretir** (Ansible gibi meşru araçlar da encoded command kullanır). Tek başına alarm değil, triage başlangıcı.
- **`-Oldest` olmadan `Get-WinEvent` en yeniden eskiye sıralar.** Kronolojik timeline için `-Oldest` gerekir.

---

## 9. Tek Bakışta Özet

| Katman | Ne sağlar | Zayıflığı |
|---|---|---|
| **Windows Event Log** | Logon, policy, servis, share, Defender event'leri; Logon ID ile korelasyon | Process/DLL seviyesinde telemetri yok |
| **Sysmon** | Process creation, network connection, image load, process access | Parent alanı spoof edilebilir; assembly içeriğini göremez |
| **ETW** | 1000+ provider, kernel seviyesinde görünürlük, method adlarına kadar detay | Karmaşıklık, hacim, session yönetimi |
| **Get-WinEvent** | Üçünü de komut satırından kitlesel sorgulama | Doğru filtre yöntemini seçmek gerekir |

**Saldırı → Log imzası eşlemesi**

| Saldırı | Nerede görünür |
|---|---|
| Brute force | `4625` (NTLM) / `4771` (Kerberos) |
| Scheduled task persistence | `4698` |
| Servis kurma | `7045` |
| Audit log temizleme | `1102` |
| DLL hijacking | Sysmon `7` — unsigned DLL, writable path |
| Process injection (.NET) | Sysmon `7` — `clr.dll` beklenmeyen process'te |
| Credential dumping | Sysmon `10` — LSASS + UNKNOWN CallTrace |
| Parent PID spoofing | ETW **Kernel-Process** (Sysmon yanılır) |
| BYOL / `execute-assembly` | ETW **DotNETRuntime** (`-uk 0x2038`) |
| Encoded PowerShell | Sysmon `1` — `Properties[21]` içinde `-enc` |

---

## Kaynaklar

- HTB Academy — *Windows Event Logs & Finding Evil* (CDSA path)
- Microsoft — Windows Security Auditing event referansları, ETW dokümantasyonu
- Sysinternals — **Sysmon**
- SwiftOnSecurity/sysmon-config, olafhartong/sysmon-modular
- FuzzySecurity — **SilkETW / SilkService**
- Mandiant — *Bring Your Own Land (BYOL)*
- Samir Bousseaden — Windows parent-child process mind map
- MITRE ATT&CK — `T1003.001`, Process Injection, Hijack Execution Flow

---

<p align="center">
  <a href="../README.md">← Tüm modüller</a>
</p>
