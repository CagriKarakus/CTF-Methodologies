---
title: "Sysmon and Windows Event ID Guide"
date: 2026-10-18
tags: [incident-response, sysmon, windows, event-id, cheatsheet]
---
# Sysmon and Windows Event ID Guide

> Phishing → execution → persistence → C2 → staging zincirini incelerken hangi Windows/Sysmon olayına **neden** bakıldığı. Bir olayı bulmak yetmez; **hangi alan neyi kanıtlar ve hangi tuzakla karıştırılır** bilinmeli. Telemetri kapsamı yapılandırmaya bağlıdır: olay yoksa önce "toplanıyor mu?" diye sor.

---

## 1. Sysmon olayları

| EID | Ad | Bu incelemede ne kanıtlar | Anahtar alanlar | Tuzak |
|---|---|---|---|---|
| 1 | ProcessCreate | Ne çalıştı, parent kim, hash ne | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `CommandLine`, `ParentImage`, `ParentProcessGuid`, `User`, `Hashes` | PID yeniden kullanılır; GUID kullan. Chrome alt süreçleri (`--type=`) |
| 2 | FileCreateTime changed | Dosyanın oluşturma zamanı değişti | `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime` | Arşivden dosya çıkarmada olağan gürültü (timestomp değil) |
| 3 | NetworkConnect | Hangi süreç hangi IP:port'a bağlandı | `Image`, `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort` | Yapılandırmada kapalı olabilir; 5156 alternatifi |
| 5 | ProcessTerminate | Süreç bitti (PID boşaldı) | `ProcessId`, `Image`, `UtcTime` | PID yeniden kullanım analizinde sıra kanıtı |
| 7 | ImageLoad | DLL yüklemesi | `Image`, `ImageLoaded`, `Hashes` | Çok gürültülü; genelde filtreli |
| 11 | FileCreate | Dosya oluşturuldu | `Image`, `TargetFilename`, `CreationUtcTime` | Hash taşımaz. İlk oluşturma satırını seç (`-Force` ile yeniden yazılır) |
| 12/13/14 | Registry | Anahtar/değer oluştu, set edildi, yeniden adlandı | `TargetObject`, `Details`, `Image` | Persistence (Run, TaskCache) |
| 15 | FileCreateStreamHash | ADS yazıldı (Zone.Identifier), dosya hash'i | `Image`, `TargetFilename`, `Hash`, `Contents`, `CreationUtcTime` | `Contents` yapılandırmaya bağlı (boş = URL yok). Hash, ADS'in bağlı olduğu dosyanındır |
| 22 | DNSQuery | Süreç bir domain sorguladı | `Image`, `QueryName`, `QueryResults` | Süreç + domain eşlemesi için çok değerli |
| 23 | FileDelete (archived) | Silinen dosya | `Image`, `TargetFilename` | `.lnk` / Recent silme-yeniden oluşturma kayıtları kullanıcı etkileşimi ipucu olabilir |
| 26 | FileDeleteDetected | Silme tespit edildi (arşivlenmeden) | `TargetFilename` | - |

### 1.1 EID 1 alanları nasıl okunur
- **`UtcTime`**: olayın zamanı (UTC, ms). Süre hesabında bunu kullan.
- **`ProcessGuid` / `ParentProcessGuid`**: benzersiz kimlik. Lineage için bunlar.
- **`ProcessId`**: ondalık PID. Security 4688'de hex görünür (`0x2b4`).
- **`Image` yolu**: `...\Temp\<n>\Temp<n>_<ad>.zip\<exe>` = arşivden çalıştırma.
- **`ParentImage = explorer.exe`**: kullanıcı çift tıkladı.
- **`Hashes`**: `MD5=...,SHA256=...,IMPHASH=...` biçimi olabilir; SHA256'yı `rex` ile ayır.
- **`User`**: `DOMAIN\kullanıcı`.

### 1.2 EID 15 zinciri (indirilen dosya)
Chrome bir dosyayı indirirken tipik olarak şu olaylar görülür: aynı `TargetFilename` için birkaç EID 15 (Zone.Identifier'ın yazım adımları), hepsi aynı hash'le. `Image=chrome.exe` ise dosyayı Chrome kaydetmiştir. `CreationUtcTime` indirmenin başlangıcıdır ve ağ logundaki HTTP olayıyla zamansal olarak örtüşür.

Extraction (Explorer, `Image=Explorer.EXE`): `TargetFilename` bir arşiv yolu içine işaret eder (`...\Temp<n>_<ad>.zip\<exe>`); burada oluşan hash **içindeki exe'nin** hash'idir, ZIP'inki değil.

---

## 2. Windows Security olayları

| EID | Ad | Ne zaman kullanılır | Not |
|---|---|---|---|
| 4688 | Process creation | Sysmon yoksa / çapraz doğrulama | Komut satırı için "Include command line in process creation events" politikası gerekir. PID **hex**; alan adları farklı (`NewProcessName`, `ParentProcessName`, `SubjectUserName`). Sysmon EID 1 ile aynı olayı iki kez göstermesi normaldir |
| 4689 | Process exit | Süreç sonu | - |
| 4698 / 4699 / 4702 | Scheduled task created / deleted / updated | Persistence teyidi | "Audit Other Object Access Events" gerekir |
| 5156 / 5157 / 5158 | WFP: bağlantı izin verildi / engellendi / bind | Ağ olayını **sürece** bağlamak | `Application` (kernel path), `SourceAddress`, `SourcePort`, `DestAddress`, `DestPort`, `Direction` (`%%14593` outbound, `%%14592` inbound). "Audit Filtering Platform Connection" gerekir; çok gürültülü |
| 4624 / 4625 | Logon başarılı / başarısız | Kapsam: hangi hesaplar nereye girdi | Logon type (2, 3, 10) ile anlam kazanır |
| 4672 | Special privileges | Yetkili logon | - |
| 7045 | Service installed (System) | Servis persistence | - |

### 2.1 4688 ile EID 1: ikisini nasıl eşleştiririz?
Aynı komut, aynı saniye civarı iki ayrı sourcetype alanı şemasıyla gelir. Sorguda alan boş görünüyorsa (örn. `Image`, `User` boş) o satır büyük ihtimalle 4688'dir. İkisini de görmek *teyit*tir, iki ayrı süreç değil. PID karşılaştırırken biçimi (hex ↔ ondalık) dönüştür.

---

## 3. Diğer kanallar

| Kanal | Olay | Ne için |
|---|---|---|
| `Microsoft-Windows-TaskScheduler/Operational` | 106 (registered), 140 (updated), 141 (deleted), 200 / 201 (action start/complete) | Görev kaydı ve çalışması |
| `Microsoft-Windows-PowerShell/Operational` | 4103 (module), 4104 (script block) | PowerShell içeriği (ScriptBlock logging açıksa) |
| `Microsoft-Windows-Sysmon/Operational` | Yukarıdaki EID'ler | Ana endpoint kanalı |
| Samba audit (Linux dosya sunucusu) | Açma / yazma / silme | Sunucu tarafı dosya erişimi: kim, hangi paylaşım, hangi yol |

---

## 4. Soru → olay eşlemesi (hızlı)

| Soru | Olay |
|---|---|
| "ZIP'i Chrome kaydederken hash ne?" | Sysmon EID 15, `Image=chrome.exe`, ZIP yolu, `Hash` |
| "Çalıştırılan loader'ın ve kopyasının ortak hash'i?" | Sysmon EID 1 `Hashes` (aynı SHA256, iki farklı yol) |
| "Zamanlanmış görev hangisi?" | Sysmon EID 1 `schtasks.exe` `CommandLine /TN`, parent loader |
| "Hangi süreç bu bağlantıyı yaptı?" | WFP 5156 (veya Sysmon EID 3) + Suricata `src_port` |
| "Arşivi hangi süreç yarattı?" | Sysmon EID 11 (`Image`, `TargetFilename`) + EID 1 komut satırı |
| "Bu PID'yi önce kim kullandı?" | Sysmon EID 1 `ProcessId=<PID>`, `ProcessGuid` farklı olan önceki satır |
| "Tarayıcıyı hangi süreç başlattı?" | Sysmon EID 1 `Image=chrome.exe`, `--type=` yok, `ParentImage` |
| "Kullanıcı dosyayı açtı mı?" | Parent `explorer.exe` + EID 1 ve `.lnk`/Recent artefaktları |

---
**Up:** [SOC Investigations - Index](SOC%20Investigations%20-%20Index.md)
**Related:** [Phishing Kill Chain - Splunk Investigation Methodology](Phishing%20Kill%20Chain%20-%20Splunk%20Investigation%20Methodology.md) · [Splunk SPL Patterns for IR](Splunk%20SPL%20Patterns%20for%20IR.md) · [Cross-Source Correlation](Cross-Source%20Correlation.md)
