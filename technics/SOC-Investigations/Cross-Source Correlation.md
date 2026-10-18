---
title: "Cross-Source Correlation"
date: 2026-10-18
tags: [incident-response, correlation, methodology, network, mail, endpoint]
---
# Cross-Source Correlation

> Tek bir log olayı bir hikâyenin cümlesidir; **hikâyeyi** kaynaklar arası ortak anahtarlarla kurarsın. Bu not "hangi iki kaynağı hangi anahtarla birleştiririm, neden güvenilir olur, nerede kırılır" sorularına cevap verir. Ana akış için: [Phishing Kill Chain - Splunk Investigation Methodology](Phishing%20Kill%20Chain%20-%20Splunk%20Investigation%20Methodology.md).

---

## 1. Ortak anahtarlar

| Anahtar | Birleştirir | Güven | Kırıldığı yer |
|---|---|---|---|
| **Domain / hostname** | mail gövdesi ↔ web log ↔ Suricata DNS/HTTP | Yüksek | Look-alike domain'ler; redirect zinciri |
| **URL / URI + dosya adı** | web log ↔ Suricata http/fileinfo ↔ Sysmon `TargetFilename` | Yüksek | Dosya adı saldırgan kontrollü; yeniden adlandırma |
| **Message-ID / queue id** | rfc822 ↔ postfix | Yüksek | Tek mesaj birden çok alıcıya gidiyorsa alıcıyı da kontrol et |
| **İstemci IP ↔ host** | ağ kaynakları ↔ endpoint | Orta | DHCP değişimi, NAT/proxy (`x_forwarded_for`) |
| **5-tuple (src_ip, src_port, dest_ip, dest_port, proto)** | Suricata ↔ WFP 5156 / Sysmon EID 3 | Çok yüksek | Zaman penceresi geniş tutulursa port yeniden kullanılabilir |
| **`flow_id`** | Suricata http ↔ fileinfo ↔ dns ↔ smb (aynı akış) | Çok yüksek | Sadece Suricata içi |
| **`ProcessGuid`** | Sysmon olayları arası (EID 1, 3, 11, 22 ...) | Çok yüksek | Sadece endpoint içi |
| **SHA256** | EID 1 ↔ EID 11/15 ↔ fleet geneli | Çok yüksek | Dosya değiştiyse (packer, yeniden derleme) hash değişir |
| **Zaman** | Her şey | Orta | NTP kayması; farklı çözünürlükler (ms, µs, saniye) |
| **SMB `tree_id` / `session_id`** | CREATE ↔ WRITE ↔ TREE_CONNECT (share adı) | Yüksek | Yeni oturum açılırsa id değişir |

---

## 2. Hangi iki kaynak, neden?

### 2.1 Mail ↔ web log: "Bu mail indirmeyi tetikledi mi?"
- **Anahtar:** Domain + yol (`/review/...`) + zaman.
- **Okuma:** Mail gövdesindeki link, indirme isteğinin `referer`'ına benzer yol taşıyorsa ve sender domain = indirme domain'iyse bağ kurulmuştur.
- **Koşul:** mail teslim zamanı < ilk istek zamanı.
- **Kırılma:** Kullanıcı linki başka kanaldan (mesaj, kısa link) almış olabilir; mail tek başına nedensellik değildir. Referer + zaman + kullanıcı eşleşmesi gücü artırır.

### 2.2 Web log ↔ Suricata: "Aynı isteği iki kaynak görüyor mu?"
- **Anahtar:** İstemci IP + URI + hostname + zaman.
- **Fark:** Web log saniye çözünürlüklü, Suricata µs. Süre hesabı ve olay sırası için **Suricata'yı** kullan.
- **Ek bilgi:** Suricata `fileinfo` indirmenin tamamlandığını (`state=CLOSED`), `size` ve MIME'ı verir.

### 2.3 Suricata ↔ WFP / Sysmon EID 3: "Hangi süreç?"
- **Anahtar:** `src_port` + `dest_ip` (+ `dest_port`) + zaman (±ms).
- **Neden güçlü:** 5-tuple aynı TCP akışını iki bağımsız vantage noktasından görür; birinde süreç, diğerinde içerik vardır.
- **Kırılma:** WFP audit kapalıysa 5156 yok; Sysmon EID 3 kapalıysa süreç atfı yapılamaz. O durumda Sysmon EID 22 (DNS sorgusu: `Image` + `QueryName`) süreç ↔ domain bağı verir.

### 2.4 Sysmon EID 15/11 ↔ Suricata: "İndirme zamanı örtüşüyor mu?"
- **Anahtar:** `CreationUtcTime` (indirmenin başlangıcı) ≈ Suricata HTTP `timestamp`; dosya adı = `fileinfo.filename`; `Image=chrome.exe`.
- **Kullanım:** Zone.Identifier `Contents` boşsa (URL yok) bu eşleme indirme domain'ini sağlar.

### 2.5 Sysmon EID 1 ↔ Suricata SMB: "Staging → exfil bağı"
- **Anahtar:** Arşiv dosya adı + zaman (EID 11 `UtcTime` → SMB WRITE `timestamp`) + `src_ip` = host IP.
- **Sunucu tarafı:** samba audit aynı dosya adını sunucu bakışıyla doğrular (kullanıcı, share, yol).

### 2.6 Endpoint içi: EID 1 ↔ 4688 ↔ 4698
- Aynı komutun üç farklı kaynakta görünmesi **teyittir**. Hex/ondalık PID dönüşümünü ve alan adı farklarını unutma.

---

## 3. Kaynak kör noktaları ve telafisi

| Eksik olan | Sonuç | Telafi |
|---|---|---|
| Sysmon `Contents` yakalanmıyor | İndirme URL'si endpoint'ten gelmez | Suricata/web log + zaman + dosya adı |
| 5156 audit kapalı | Ağ ↔ süreç bağı yok | Sysmon EID 3, EID 22 |
| TLS | Suricata içerik/URL göremez | DNS (EID 22 / Suricata dns), SNI/JA3, proxy logu |
| Komut satırı denetimi kapalı (4688) | Komut yok | Sysmon EID 1 |
| Mail ham içerik yok | Link/başlık görünmez | MTA logları (postfix) + Message-ID |
| NTP kayması | Sıra tutmaz | Aynı bağlantıyı iki kaynakta ölçerek kayma bul |

---

## 4. Korelasyon sırası (pratik)

1. **Çapa**: tek bir sağlam olay (EID 1: arşiv içi exe).
2. **Geri**: indirme (Sysmon + Suricata) → referer/URL → mail (domain → Message-ID → teslim).
3. **İleri**: loader çocukları → kopya/hash → görev → C2 isteği → akış eşleşmesi (5-tuple).
4. **Yana**: aynı IOC başka host'ta var mı (UA, domain, hash, görev adı)?
5. **Doğrula**: her halka ≥2 bağımsız kaynakta mı?

---

## 5. Zaman hizalama (clock skew) kontrolü

İki kaynağın saati kayık olabilir. Bir referans bağlantıyı iki kaynakta ölç (örn. aynı TCP akışı Suricata'da ve WFP'de): iki zaman damgası arasındaki fark, o iki kaynağın kayma + işleme gecikmesidir. Küçük (ms) ve tutarlıysa karşılaştırma güvenlidir. Büyükse tüm süre hesaplarını **aynı kaynak içinde** yap (örn. hem başlangıç hem bitiş Suricata'dan).

---

## 6. Güven seviyelerini rapora yansıt

- **Kanıtlı:** İki bağımsız kaynakta, ortak anahtarla doğrulanmış (örn. aynı `src_port` + `dest_ip` iki kaynakta, süreç adı WFP'den).
- **Güçlü ipucu:** Tek kaynakta, bağlamla tutarlı (örn. mail linki ↔ referer, zaman uyumlu).
- **Çıkarım:** Davranıştan çıkan sonuç (örn. "failover implant'a gömülü olabilir").

Bulgu raporunda bu üçünü ayrı yaz; karşı tarafın karar vermesi gereken noktada hangisine dayandığın görünsün.

---
**Up:** [SOC Investigations - Index](SOC%20Investigations%20-%20Index.md)
**Related:** [Phishing Kill Chain - Splunk Investigation Methodology](Phishing%20Kill%20Chain%20-%20Splunk%20Investigation%20Methodology.md) · [Splunk SPL Patterns for IR](Splunk%20SPL%20Patterns%20for%20IR.md) · [Sysmon and Windows Event ID Guide](Sysmon%20and%20Windows%20Event%20ID%20Guide.md)
