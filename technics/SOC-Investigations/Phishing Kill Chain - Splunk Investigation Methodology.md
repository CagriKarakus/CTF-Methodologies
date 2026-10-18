---
title: "Phishing Kill Chain - Splunk Investigation Methodology"
date: 2026-10-18
tags: [incident-response, soc, splunk, sysmon, suricata, phishing, methodology, threat-hunting]
---
# Phishing Kill Chain - Splunk Investigation Methodology

> Bu not **bir makineye veya odaya özel değil**. "Phishing maili → indirme → loader çalıştırma → persistence → C2 → staging/exfil" zincirini Splunk'ta çok kaynaklı loglarla baştan sona **kanıtlamanın yöntemi**. Amaç: benzer bir olayda "hangi soruyu, hangi kaynağa, neden ve nasıl sorarım?" sorusunun cevabı bu notta bulunsun. Örneklerdeki değerler uydurmadır (`WS-FIN-01`, `jdoe`, `lure-review.example`, `c2-primary.example` ...). Sorgu şablonları `<ANGLE_BRACKET>` placeholder kullanır.

Yan notlar: [SPL kalıpları](Splunk%20SPL%20Patterns%20for%20IR.md) · [Sysmon & Windows Event ID rehberi](Sysmon%20and%20Windows%20Event%20ID%20Guide.md) · [Kaynaklar arası korelasyon](Cross-Source%20Correlation.md)

---

## 0. TL;DR

1. **Önce veriyi tanı, sonra soru sor.** Hangi sourcetype var, alan adları ne, hangi zaman damgası hangi çözünürlükte? (Bölüm 2)
2. **Endpoint'te process creation (Sysmon EID 1) ile çapa at**, oradan *geriye* (indirme → mail) ve *ileriye* (persistence → C2 → staging) genişlet. (Bölüm 1.4)
3. **Her halkayı en az iki bağımsız kaynakta doğrula.** Endpoint süreci bilir ama ağ içeriğini bilmez; ağ içeriği bilir ama süreci bilmez. İkisini ortak anahtarla (zaman + IP + port + hash + domain) birleştir. (Bölüm 4.9, [Korelasyon](Cross-Source%20Correlation.md))
4. **Zamanda olayın kendi damgasını kullan** (`UtcTime`, Suricata `timestamp`), Splunk `_time`'ını değil; çözünürlükleri (ms / µs / saniye) bil. (Bölüm 5)
5. **PID değil `ProcessGuid`; ad değil soyağacı (lineage); ZIP hash'i ≠ içindeki exe hash'i.** (Bölüm 4.5, 4.12)
6. **Cevap kalıbı:** istenen alanı taşıyan olayı bul → `_raw` ile doğrula → karıştırılabilecek *kardeş olayları* bilinçli ele (request/response, CREATE/WRITE, 503/204, Sysmon/4688).

---

## 1. Zihniyet

### 1.1 Kanıt zinciri (evidence chain)
İnceleme, "A, B'yi tetikledi" iddialarından oluşan bir zincirdir. Her halka üç şeyle kurulur:

- **Nedensellik:** Parent/child, referer, aynı flow, aynı hash.
- **Zaman sırası:** Neden sonuçtan önce gelmeli (mail < tıklama < indirme < çalıştırma).
- **Ortak anahtar:** İki kaynağı aynı olaya bağlayan değer (IP, port, hash, domain, ProcessGuid, Message-ID).

Hiçbir log tek başına zinciri kanıtlamaz; her kaynağın **kör noktası** vardır:

| Kaynak | Görür | Kör noktası |
|---|---|---|
| Mail MTA/gateway (postfix, rfc822) | Kim kime ne gönderdi, linkler, Message-ID, teslim durumu | Alıcının tıklayıp tıklamadığı |
| Web / proxy logu (örn. nginx JSON) | Hangi istemci hangi URI'yi hangi User-Agent ve Referer ile çekti, status, boyut | İstemcide hangi *process* olduğu |
| Suricata / Zeek | Akış düzeyi HTTP, DNS, SMB, fileinfo; 5-tuple; µs zaman | Şifreli (TLS) içerik; süreç kimliği |
| Sysmon | Process, dosya, registry, ADS, DNS sorgusu (EID 22), bağlantı (EID 3) | Ağ içeriği; yapılandırmaya bağlı kapsama |
| Windows Security (4688, 4698, 5156) | Süreç + komut satırı, görev oluşumu, WFP bağlantı + uygulama yolu | Audit politikası kapalıysa hiç yok |
| Dosya sunucusu audit (samba) | Sunucuda kim hangi paylaşımda hangi dosyayı açtı/yazdı | İstemcideki süreç |

### 1.2 Soruyu sorgu planına çevir
Her soruyu beş parçaya ayır:

1. **Özne:** Hangi dosya / süreç / domain? (ZIP mi, içindeki exe mi?)
2. **Olay türü:** Hangi event / sourcetype? (EID 15 mi, EID 11 mi, EID 1 mi?)
3. **Zaman penceresi:** Neyden önce / sonra?
4. **İstenen alan ve format:** Hash, port, dosya adı, saniye farkı, "baştaki `\` olmadan"?
5. **Tuzak kardeşler:** Aynı şeye benzeyen ama cevap olmayan olaylar (request vs response, CREATE vs WRITE, 4688 vs EID 1).

Örnek: "Chrome ZIP'i kaydederken Sysmon'un file-stream hash olayının SHA-256'sı" → özne **ZIP** (loader değil), olay **EID 15**, Image **chrome.exe**, alan **SHA256**; tuzaklar: ZIP içindeki exe'nin hash'i, EID 11 (hash taşımaz), EID 1 `Hashes`.

### 1.3 Giriş noktasına göre başlangıç yönü

| Elimdeki ipucu | İlk bakılacak yer | Yön |
|---|---|---|
| Şüpheli mail bildirimi | rfc822 + postfix | İleri: web log → endpoint |
| TI'dan şüpheli domain / IP | Web/proxy log, Suricata DNS, WFP 5156 | Hem geri (mail) hem ileri |
| EDR/AV alarmı: bir exe | Sysmon EID 1 | Geri (parent, indirme) + ileri |
| Ağda periyodik trafik (beacon) | Web log UA/URI → WFP / Sysmon 3 ile süreç | Geri (süreç → loader → mail) |
| Paylaşımda tuhaf arşiv | samba audit / Suricata SMB | Geri: client IP → süreç → komut satırı |
| Bilinen hash | Sysmon EID 1/11/15 `Hashes` | Fleet geneli yayılım + geri |

### 1.4 Neden endpoint'te çapa, neden geriye?
Process creation kaydı en az belirsiz ve en çok bağlam taşıyan gözlemdir: `Image`, `CommandLine`, `ParentImage`, `User`, `Hashes`, `ProcessGuid`. Buradan:

- `ParentImage = explorer.exe` → kullanıcı etkileşimi (çift tık). `Image` yolundaki `...\Temp\<n>\Temp<n>_<ad>.zip\<exe>` → *arşivin içinden* çalıştırıldı → ZIP adı elimizde.
- ZIP adı → indirme olayı (Sysmon EID 15/11, Suricata/web log) → URL, domain, referer.
- Domain → mail loglarında aynı domain'den gelen mail → Message-ID.

Yani zinciri **bilinen en sağlam uçtan** başlatıp bilinmeyene doğru uzatırsın; mail logunda *domain* araması ham veride körlemesine "legal review" aramaktan çok daha dardır.

---

## 2. Başlamadan önce: ortamı tanı

### 2.1 Envanter
```spl
index=* | stats count min(_time) as first max(_time) as last by index, sourcetype
| convert ctime(first) ctime(last)
```
Sourcetype adları genelde ne olduğunu söyler (`*:mail:postfix`, `*:mail:rfc822`, `*:web:nginx:json`, `*:network:suricata:json`, `*:windows:xml`, `*:files:samba:audit`). Kaç tane olay var? Küçük sourcetype (örn. yalnızca birkaç düzine ham mail) **önce taranacak** yerdir.

### 2.2 Alan adlarını varsayma, ham olayı gör
```spl
index=* sourcetype="<ST>" | head 3 | table _raw
index=* sourcetype="<ST>" | fieldsummary maxvals=5 | table field count distinct_count values
```
- Aynı kavram kaynağa göre farklı adlanır: `Image` / `NewProcessName`, `ParentImage` / `ParentProcessName`, `http.hostname` / `server_name` / `http_host`, `src_ip` / `client_ip` / `SourceAddress`.
- Sütun boş çıkıyorsa **sorgun yanlış değil, alan o sourcetype'ta başka adla duruyor** olabilir: `_raw`'a bak.
- Çıkarılmamış alan için `rex`:
```spl
| rex field=_raw "Name=['\"]Hashes?['\"]>(?<hashes>[^<]*)"
| rex field=hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
```

### 2.3 Zaman damgası türleri (karıştırılırsa yanlış cevap)

| Alan | Kaynak | Çözünürlük | Not |
|---|---|---|---|
| `_time` | Splunk | genelde ms | Indexleme/parsing zamanı olabilir, olayın gerçek zamanından birkaç ms sapabilir |
| `UtcTime` | Sysmon (olay gövdesi) | ms | **Süre farkı hesabında bunu kullan** |
| `CreationUtcTime` | Sysmon EID 11/15 | ms | Dosya oluşturma zamanı; arşivden çıkarılan dosyada arşivdeki zaman damgasını taşıyabilir (bkz. 4.2) |
| `timestamp` | Suricata EVE | µs, `+0000` | En hassas kaynak |
| `time` | nginx JSON | **saniye** | Milisaniye farkı hesaplamada yetersiz; Suricata'daki karşılığını kullan |

### 2.4 Host ↔ IP ↔ kullanıcı eşlemesi
Ağ kaynakları IP bilir, endpoint kaynakları host adı. Önce eşle: WFP 5156 `SourceAddress`, Sysmon EID 3 `SourceIp`, DHCP/DNS logları. Örnek: `WS-FIN-01 = 10.0.0.50`. Bu eşleme olmadan Suricata ile Sysmon'u birleştiremezsin. NAT/proxy varsa `x_forwarded_for` alanını da kontrol et (boşsa `client_ip` gerçek istemcidir).

### 2.5 Zaman aralığı
**All time** ile başla, sonra `earliest=` / `latest=` ile daralt. Neden all time: PID yeniden kullanımı saatler/günler önce olabilir, persistence haftalar sonra tetiklenir, saldırı hazırlığı olaydan günler önce başlamış olabilir.

---

## 3. Kill chain haritası

| # | Aşama | Soru | Birincil kaynak | Doğrulayıcı kaynak | Anahtar alan / pivot |
|---|---|---|---|---|---|
| 1 | Delivery | Mail ulaştı mı? | postfix status + rfc822 | - | Message-ID, queue id, From / Return-Path |
| 2 | Click / landing | Kullanıcı nereye gitti? | Web log `referer`, Suricata http | Chrome başlatan süreç (EID 1) | referer, hostname, url |
| 3 | Download | ZIP nereden, ne zaman, hangi hash? | Suricata http+fileinfo, web log | Sysmon EID 15/11 (Chrome) | URL, `flow_id`, SHA256 (EID 15), boyut |
| 4 | Execution | Hangi exe, hangi parent? | Sysmon EID 1 | Security 4688; EID 2/11/15 (extraction) | Image, ParentImage, ProcessGuid, Hashes |
| 5 | Install / persistence | Kopya, görev, registry? | EID 1 (schtasks), EID 11/13 | Security 4698, TaskScheduler 106 | CommandLine `/TN`, TargetFilename, hash eşleşmesi |
| 6 | C2 beaconing | İlk callback, aralık, domain? | Web/proxy log + Suricata | WFP 5156 / Sysmon EID 3 / EID 22 | server_name, UA, URI, status, src_port |
| 7 | Failover | Birincil düştü mü, yedek ne? | Web log status + Suricata DNS | WFP / EID 22 | status (503), DNS answer `rdata` |
| 8 | Staging | Neyi arşivledi, hangi süreç? | EID 1 (powershell) | Security 4688, EID 11 | CommandLine, ParentImage, TargetFilename |
| 9 | Internal exfil | Arşiv nereye yazıldı? | Suricata SMB | samba audit, EID 3 | smb.command/status/filename, dest_ip |

---

## 4. Aşama aşama: nereye, neden, nasıl

### 4.1 Çapa: ZIP içinden çalışan program

**Neye bakılır:** Sysmon EID 1 içinde `Image` veya `CommandLine` yolu bir arşivin içini gösteren süreçler.

**Neden:** Kullanıcı arşive çift tıklayıp içindeki exe'yi başlattığında Windows (Explorer'ın "sıkıştırılmış klasör" desteği) içeriği geçici dizine açar ve exe'yi oradan çalıştırır. Yol kendisi bir kanıt olur:
`C:\Users\<user>\AppData\Local\Temp\<n>\Temp<n>_<arşiv adı>.zip\<exe>`.
Diğer arşiv araçlarında da benzer geçici desenler çıkar (`7zO*`, `Rar$DI*`); desenleri genişlet.

**Nasıl:**
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1
  (Image="*.zip\\*" OR CommandLine="*.zip\\*")
| table _time UtcTime host User Image CommandLine ParentImage ProcessGuid
```

**Nasıl okunur:**
- `ParentImage = C:\Windows\explorer.exe` → kullanıcı çift tıkladı (otomatik değil).
- Yolun içindeki `Temp<n>_<ad>.zip` → ZIP adı = bir sonraki pivot.
- Aynı komut iki satır görünüyor ve biri boş alanlı mı? İkincisi büyük ihtimalle **Security 4688** (alan şeması farklı: `NewProcessName`, `SubjectUserName`...). Aynı olayın iki kaynaktaki kaydıdır, iki ayrı süreç değil.

**Tuzaklar:** Dikkat dağıtıcı meşru ZIP indirmeleri (iç domain, BITS ile şablon indirme, parent'ı kurumsal yazılım) aynı ekranda görünebilir. Ayırt edici: parent zinciri, indirme domain'i, kullanıcı etkileşimi (`explorer.exe` parent'ı).

### 4.2 İndirme: hem endpoint hem ağ

**Endpoint tarafı (Sysmon):**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode IN (11,15) TargetFilename="*<zip_adı>*"
| table _time UtcTime EventCode Image TargetFilename CreationUtcTime Hash Contents
```
- **EID 15 (FileCreateStreamHash):** Chrome, indirmeyi *Zone.Identifier* alternatif veri akışıyla (ADS) işaretler (Mark-of-the-Web). `Image=chrome.exe` ise dosyayı Chrome kaydetti. `Hash` = **ZIP'in** hash'i. Aynı dosya için birkaç EID 15 üst üste gelebilir (yazma + rename adımları) ve hash hepsinde aynıdır.
- `Contents` alanı yalnızca Sysmon yapılandırması ADS içeriğini yakalıyorsa dolar. **Boşsa `HostUrl` / `ReferrerUrl` endpoint'ten gelmez**; indirme domain'ini ağ kaynaklarından al.
- `CreationUtcTime` ≈ indirmenin başladığı an; Suricata HTTP olayının zamanıyla birkaç ms içinde örtüşebilir. Pencere kurmak için çok kullanışlıdır.
- **Extraction ile oluşan EID 2/11/15 (Explorer):** Arşivden çıkarılan dosya, arşivdeki orijinal zaman damgasını taşıyabilir. `CreationUtcTime` indirme zamanından *önce* görünürse timestomping sanma; **EID 2 (creation time changed) arşiv açma gürültüsüdür**.

**Ağ tarafı:** Sysmon domain vermiyorsa ZIP adıyla ağ kaynaklarına git. `NOT EventCode=*` Windows olaylarını eler (onlarda `EventCode` var), geriye web/ağ/mail kalır:
```spl
index=* "<zip_adı>" NOT EventCode=*
| table _time sourcetype _raw
```
Beklenen: web logu + Suricata `http` + Suricata `fileinfo`. Önemli alanlar:
- Web log: `server_name` / `http_host`, `uri`, `referer`, `client_ip`, `status`, `bytes_sent`, `user_agent`.
- Suricata `http`: `http.hostname`, `http.url`, `http.http_refer`, `http.http_content_type` (`application/zip`), `src_ip`, `flow_id`.
- Suricata `fileinfo`: `fileinfo.filename`, `fileinfo.size`, `fileinfo.state=CLOSED` (indirme tamamlandı). Aynı `flow_id` ile http olayına bağlanır.

**Referer neden altın değerinde:** İndirme sayfası referer'ı (örn. `/review/disclosure-schedule`) kullanıcının *bir sayfadan* geldiğini gösterir; bu sayfa mail içindeki linkle aynı yolu taşır → mail ile indirme arasındaki halka.

**Tuzaklar:**
- ZIP hash'i (EID 15, Chrome) ≠ içindeki exe hash'i (EID 15/11, Explorer ya da EID 1).
- `Disclosure_...zip` ve `Temp1_Disclosure_...zip` farklı yollar: ilki indirilen dosya, ikincisi Explorer'ın açtığı geçici kopya.

### 4.3 Mail: lure mailini kanıtla

**Neye bakılır / neden iki sourcetype?**
- **rfc822 (ham mail):** `From`, `Return-Path`, `Reply-To`, `Subject`, `Message-ID`, `Received`, `Authentication-Results`, gövdedeki linkler. Hacim küçüktür: **ilk burada ara**.
- **postfix (MTA logu):** kuyruk ve teslim: `status=sent|deferred|bounced|rejected`. Hacim büyüktür: sadece *Message-ID ile daralt*.

**Nasıl:**
```spl
index=* sourcetype="<RFC822_ST>" "<lure-domain>"
| table _time _raw
```
Sonra teslimi doğrula. Postfix'te her mesajın tüm satırları aynı **queue id**'yi taşır; `message-id=<...>` satırı queue id'yi verir:
```spl
index=* sourcetype="<POSTFIX_ST>"
| rex "\]:\s(?<qid>[0-9A-Za-z]+):\s"
| rex "message-id=<(?<msgid>[^>]+)>"
| rex "from=<(?<mfrom>[^>]*)>"
| rex "to=<(?<rcpt>[^>]*)>"
| rex "status=(?<status>\w+)"
| where isnotnull(qid) AND qid!="warning"
| stats min(_time) as first values(msgid) as msgid values(mfrom) as mfrom values(rcpt) as rcpt values(status) as status by qid
| search msgid="<MESSAGE_ID_BEZ_ACILI_PARANTEZ>"
```

**Aday mailleri eleme kriterleri (aynı domain'den çok mail çıkabilir):**
1. **Sender domain birebir** indirme domain'iyle aynı mı? (`lure-review.example` ≠ `lure-reviews.example`; look-alike kampanyalar yaygındır.) Sadece gövdesinde link geçen ama başka domain'den gelen mail cevap değildir.
2. Alıcı etkilenen kullanıcı mı?
3. Teslim: `status=sent`. Reddedilen / karantinaya alınan / bounce edilen mail kullanıcıya ulaşmadı.
4. Zaman: teslim < tıklama < indirme.
5. Gövdede indirme sayfasına giden link var mı?

**Message-ID formatı:** Genelde `<...@domain>`. İstenen formatta köşeli parantezleri at.

### 4.4 Linke tıklayınca tarayıcıyı kim başlattı?
Mail teslimi ile indirme arasındaki aralıkta chrome'un ana sürecini bul:
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1 Image="*chrome.exe"
  NOT CommandLine="*--type=*"
| table _time UtcTime Image CommandLine ParentImage ParentCommandLine
| sort _time
```
- `--type=renderer|gpu-process|utility...` içeren satırlar Chrome'un alt süreçleri; parent'ları yine `chrome.exe` olur, **cevap bunlar değil**. `--type=` içermeyen ana süreci al.
- `CommandLine` içinde indirme URL'si geçebilir (link doğrudan tarayıcıya argüman olarak verilmişse).
- Parent genelde mail istemcisi (örn. `OUTLOOK.EXE`) ya da `explorer.exe`. **Tahmin etme, `ParentImage`'dan oku.** Chrome zaten açıksa link açma yeni bir kısa ömürlü launcher süreci doğurup mevcut örneğe devredebilir; bu da EID 1'de görünür.

### 4.5 Loader davranışı ve hash pivotu

**Neye bakılır:** Loader'ın çocukları (child), yazdığı dosyalar ve kendi hash'i.
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1
  (ParentProcessGuid="<LOADER_GUID>" OR ProcessGuid="<LOADER_GUID>")
| table _time UtcTime Image CommandLine ParentImage ProcessGuid
```
Tipik davranışlar: `rundll32.exe` / `schtasks.exe` çocukları (persistence, payload yükleme), kendini `AppData\Local\<ad>\<ad>.exe` altına kopyalama.

**Hash pivotu (en güvenilir "aynı program" kanıtı):**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode IN (1,11,15)
| rex field=_raw "Name=['\"]Hashes?['\"]>(?<hashes>[^<]*)"
| rex field=hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| where sha256="<LOADER_SHA256>"
| table _time EventCode Image TargetFilename sha256
```
Loader exe'nin hash'i ile "yüklü sync client"ın hash'i **aynıysa**, sync client loader'ın kopyasıdır: dosya adı ve yolu masum görünse de içerik aynıdır. Soru "process-creation olaylarında paylaşılan SHA-256" diyorsa cevabı EID 1 `Hashes`'ten doğrula (EID 15'te de aynı hash görünür, ama kaynağı belirtilen olaydan al).

**Tuzak:** Üç ayrı hash vardır: **ZIP hash'i** (indirme, EID 15 Chrome), **loader exe hash'i** (açılış, EID 15/11 Explorer + EID 1), **kopya exe hash'i** (EID 1). Hangisi istendiğini 1.2'deki parçalamayla netleştir.

### 4.6 Persistence: zamanlanmış görev

**Neden schtasks?** Saldırgan yeniden başlatmada hayatta kalmak için görev ekler; ad genelde *meşru bir yazılımı taklit eder* (masquerading). Saldırı tarafı için: [SCHtask](../Windows%20persistence/SCHtask.md).

**Nasıl:**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1 Image="*\\schtasks.exe"
| rex field=CommandLine "(?i)/tn\s+\"?(?<task_name>[^\"/]+)"
| table _time UtcTime ParentImage CommandLine task_name
```
**Okuma:** `/TN` görev adı, `/TR` çalışacak komut, `/SC` zamanlama (ONLOGON, MINUTE...). Çıktıda başında `\` olan adlar normaldir (`\Klasör\Ad`); soru "baştaki `\` olmadan" diyorsa kırp.

**Rutin görevden ayırma (kritik):** Meşru yazılımın da görevleri olabilir. **Karar kriteri ad değil soyağacıdır:** `ParentImage` loader / implant mı, yoksa kurumsal yazılımın kendi süreci mi? Ayırt edici çapraz doğrulama:
- Security **4698** (task created; "Audit Other Object Access Events" gerekir).
- `Microsoft-Windows-TaskScheduler/Operational` **106** (registered), **200/201** (action started/completed).
- Sysmon registry: `TargetObject="*\\Schedule\\TaskCache\\Tree\\*"` (EID 12/13); yazan süreç genelde `svchost.exe`.
- Dosya: `C:\Windows\System32\Tasks\<ad>` (EID 11).

Zaman damgası ipucu: `schtasks.exe` çocuğu loader'ın başlangıcından saniyeler içinde görünüyorsa kurulum otomatik (script) yapılmıştır.

### 4.7 C2 beaconing

**Neye bakılır:** İstemci IP'sinin, özel bir User-Agent ile, aynı URI'ye, düzenli aralıklarla yaptığı istekler.
```spl
index=* sourcetype="<WEB_ST>" client_ip="<WS_IP>" earliest="<LOADER_START>"
| table _time server_name http_host uri method status user_agent referer
| sort 0 _time
```
**Okuma:**
- **User-Agent** tarayıcı değil, uygulamaya özel (`<App>/4.1`). Aynı UA hunt için pivot.
- **URI** sabit, query parametreleri sabit (tenant/channel gibi); yanıt hep küçük (`204 No Content`) → "check-in".
- **Domain**: ZIP'i sunan domain'den **farklı** olabilir; look-alike ya da CDN gibi görünen ad (`cdn-...`, `api-...`).
- **Aralık**: düzenli (biraz jitter'lı). Hesaplamak için:
```spl
index=* sourcetype="<WEB_ST>" client_ip="<WS_IP>" user_agent="<UA>"
| sort 0 _time
| streamstats current=f last(_time) as prev by server_name
| eval delta=round(_time-prev,1)
| table _time server_name status delta
```
Düşük `stdev(delta)/avg(delta)` oranı beacon işaretidir.

**Başlangıç gecikmesi (loader'ın sleep'i):** İlk callback'in zamanından sync client'ın **EID 1 `UtcTime`**'ını çıkar. Neden `UtcTime`? Çünkü Splunk `_time`'ı birkaç ms farklı olabilir ve nginx zaman damgası saniye çözünürlüklüdür; fark hesabında sonuç tam saniyeye yuvarlanıyorsa bu hassasiyet yeterlidir ama **kesirlerle birlikte hesapla, sonra yuvarla**. Ayrıntı: Bölüm 5.

### 4.8 Failover: birincil C2 çökünce yedek domain

**Belirti:** Birincil domain'e giden istek `503` döner; **aynı saniye içinde** yedek domain'e istek görülür.
```spl
index=* sourcetype="<SURICATA_ST>" event_type=dns "<yedek-domain>"
| table timestamp dns.type dns.rrname dns.answers{}.rrtype dns.answers{}.rdata
```
**Okuma:**
- Suricata EVE sürümüne göre `dns.type` değeri `request`/`response` (v2) ya da `query`/`answer` (v1) olabilir. **Cevap kaydı = `response`/`answer` + `rrtype=A`**. Request satırı birkaç yüz µs önce görünür ve *cevap değildir*.
- Aynı sorguya AAAA cevabı da gelebilir; `A` olanı ayır.
- **503 zamanını** web logundan değil, **Suricata http** olayından al (µs çözünürlük). Fark: `503_timestamp - DNS_response_timestamp`.
- DNS çözümü 503'ten *önce* ise (ms mertebesinde) istemci yedek domain'i **önceden hazırlıyor/aynı anda çözüyor** demektir: failover mantığı implant'a gömülü olabilir. Çıkarım olarak yaz, kanıt gibi sunma.

### 4.9 Akış düzeyinde korelasyon: ağ olayını sürece bağla

Ağ logu (Suricata) süreci bilmez, WFP/Sysmon bilir. Aynı bağlantıyı iki tarafta eşleştir:

**Ağ tarafı:**
```spl
index=* sourcetype="<SURICATA_ST>" event_type=http "<c2-domain>" earliest="<T1>" latest="<T2>"
| table timestamp src_ip src_port dest_ip dest_port http.hostname http.url http.status
```
**Endpoint tarafı (WFP allowed connection):**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=5156 earliest="<T1>" latest="<T2>"
| table _time Application SourceAddress SourcePort DestAddress DestPort Direction
```
**Eşleştirme:** `SourcePort = src_port` **ve** `DestAddress = dest_ip` **ve** `Application` = implant yolu. Bu üçlü uyumu, "bu HTTP isteğini hangi süreç yaptı?" sorusunu kapatır.

Notlar:
- `Application` yolu kernel formatında gelir (`\device\harddiskvolume1\...`, küçük harf). Sorguda wildcard ile ara.
- `Direction`: `%%14593` = outbound, `%%14592` = inbound.
- Aynı pencerede `svchost.exe` ile görünen `DestPort=53` satırları DNS çözümleme trafiğidir, cevap değil.
- 5156 yalnızca "Audit Filtering Platform Connection" açıksa vardır ve çok gürültülüdür; daima dar zaman penceresi kullan. Alternatif: Sysmon EID 3 (`SourcePort`, `DestinationIp`).
- Her yeni beacon yeni TCP bağlantısı açar → `src_port` her seferinde farklıdır. "İlk başarılı callback" için **ilk 2xx** isteği seç; 503'lü veya başarısız denemeleri ele.

### 4.10 Staging: toplama ve arşivleme

**Neye bakılır:** Implant'ın çocuğu olarak çalışan arşivleme komutu.
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1 Image="*\\powershell.exe"
  CommandLine="*Compress-Archive*"
| table _time UtcTime ProcessId ProcessGuid ParentImage ParentProcessId CommandLine
```
**Okuma:**
- `-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "Compress-Archive -Path '<klasör>\*' -DestinationPath '<arşiv>.zip' -Force"` kalıbı: otomasyon, kullanıcı değil.
- `ParentImage` implant'tır → insan değil, C2 komutu.
- Arşivin diske yazıldığı olay: EID 11, `Image=powershell.exe`, `TargetFilename=<arşiv>.zip`. **İlk oluşturma satırını** al (`-Force` yeniden yazabilir).
- Aynı komut hem Sysmon EID 1 hem Security 4688'de görünür; 4688'de PID **hex**, Sysmon'da ondalıktır.

### 4.11 Internal exfil: SMB'ye yazma

**Neden Suricata SMB?** Dosya sunucusuna taşıma istemci–sunucu SMB2 trafiğidir; Suricata komut düzeyinde görür.
```spl
index=* sourcetype="<SURICATA_ST>" event_type=smb "<arşiv_adı>"
| table timestamp src_ip dest_ip smb.command smb.status smb.filename smb.share _raw
```
**Okuma:**
- Tipik sıra: `SMB2_COMMAND_CREATE` (disposition `FILE_OVERWRITE_IF` = yeni/üzerine yazma) → `SMB2_COMMAND_WRITE` → CLOSE. Sonraki `CREATE` + `FILE_OPEN` = dosyanın tekrar açılması (okuma/doğrulama).
- **"Successful WRITE":** `smb.command=SMB2_COMMAND_WRITE` **ve** `smb.status=STATUS_SUCCESS`. CREATE/CLOSE/SET_INFO ya da başarısız yazmalar cevap değil.
- `smb.share` WRITE satırında boş olabilir; paylaşım adı daha önceki `SMB2_COMMAND_TREE_CONNECT` olayında geçer. `tree_id` / `session_id` / `flow_id` ile bağla.
- Dosya sunucusu kimliği: `dest_ip` (aynı IP DNS/SMB'de başka rol de üstlenebilir; hosts eşlemesinden doğrula).
- Sunucu tarafı teyit: `samba:audit` (kim, hangi paylaşım, hangi yol).
- **Süre hesabı:** Sysmon EID 11 `UtcTime` → Suricata WRITE `timestamp`; "whole seconds" için önce kesirli farkı hesapla, soru yuvarlama mı kesme mi istiyor ona göre `round`/`floor` uygula.

### 4.12 PID yeniden kullanımı: "bu PID'yi önceki kullanan kimdi?"

Windows, biten sürecin PID'sini yeni sürece verebilir. Bu yüzden **PID bir kimlik değildir; `ProcessGuid` kimliktir.**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1 ProcessId=<PID>
| table _time UtcTime ProcessId Image ProcessGuid
| sort - UtcTime
```
Okuma:
- Listede **hedef sürecin kendi satırı** (aynı `ProcessGuid`) en üste gelir; onu ve sonrasını atla.
- Hemen altındaki satır, hedeften *önce* o PID'yi son kullanan süreçtir.
- Bu ilişki **soyağacı değil tesadüf**tür (örn. bir tarayıcı yardımcı servisi). Gerçek parent için `ParentProcessId`/`ParentProcessGuid`'e bak.
- `EID 5` (process terminated) ile PID'nin boşalma sırasını doğrulayabilirsin.
- Dikkat: `ProcessId=<PID>` filtresi `ParentProcessId` alanını yakalamaz; ama düz metin aramasında (`"<PID>"`) yakalar. Parent olarak o PID'yi kullananları cevap sayma.

---

## 5. Zaman matematiği

Süre sorularında (örn. "start ile ilk callback arası", "DNS cevabı ile 503 arası", "arşiv yazımı ile SMB WRITE arası") şu kuralı uygula:

1. **Her iki ucu da olayın kendi alanından al** (`UtcTime`, Suricata `timestamp`).
2. **Aynı çözünürlükteki kaynaklarla karşılaştır** (ms-ms, µs-µs). Mümkünse nginx (saniye) yerine Suricata (µs) kullan; mecburen karıştırıyorsan sonucu yorumla ("saniye çözünürlüğü nedeniyle ±1 sn").
3. **Önce kesirli farkı hesapla, sonra yuvarla**:
```spl
| makeresults
| eval t1=strptime("<ISO_UTCTIME_1>","%Y-%m-%d %H:%M:%S.%3N")
| eval t2=strptime("<ISO_TIMESTAMP_2>","%Y-%m-%dT%H:%M:%S.%6N%z")
| eval diff_s=round(t2-t1,3), diff_ms=round((t2-t1)*1000,3)
| eval diff_whole_floor=floor(t2-t1), diff_whole_round=round(t2-t1,0)
```
4. "Whole seconds" / "rounded to the nearest second" / "to three decimal places" cümlesindeki **biçim isteğini cevaba aynen uygula**.
5. İşaret kontrolü: fark pozitif çıkmalı (olay sırası beklenenle uyumlu). Negatifse uçları ters almışsındır.
6. Zaman dilimi: Sysmon `UtcTime` UTC, Suricata `+0000`, nginx JSON `+00:00`. Splunk arayüzünün saat dilimi kayması yaratmaması için bunları **metin olarak** parse et.

---

## 6. Sorgu yazma stratejisi

- **Dardan genişe:** önce tek host + tek pencere, sonra genişlet.
- **`NOT EventCode=*`** = Windows dışı kaynaklar (web, mail, ağ).
- **Alan boşsa `_raw`**: sütun boş = o sourcetype'ta başka adla tutuluyor olabilir.
- **JSON alan notasyonu:** `http.hostname`, `dns.answers{}.rdata`, `fileinfo.filename`. Süslü parantez dizi elemanı içindir.
- **Çok kaynaklı anahtar:** `host` (endpoint), `src_ip/client_ip` (ağ), `ProcessGuid` (süreç), `flow_id` (ağ akışı), `Message-ID` (mail).
- **Doğrulama sorgusu yaz:** her bulguyu ikinci, bağımsız bir sorguyla (başka sourcetype) teyit et.
- **Sonuç sayısını kontrol et:** beklenmedik tek satır ya da yüzlerce satır, filtrenin yanlış olduğunu gösterir.
- Daha fazla kalıp: [Splunk SPL Patterns for IR](Splunk%20SPL%20Patterns%20for%20IR.md).

---

## 7. Sık düşülen tuzaklar

| Tuzak | Sonuç | Önlem |
|---|---|---|
| ZIP hash'i ile içindeki exe hash'ini karıştırmak | Yanlış IOC | Olay türü + `Image` + `TargetFilename` ile hangi dosya olduğunu doğrula |
| Request satırını DNS "cevabı" sanmak | Süre sapması (µs-ms) | `dns.type=response/answer` |
| CREATE'i WRITE sanmak | Yanlış süre | `smb.command` + `smb.status` |
| `_time` kullanmak | ms sapması | `UtcTime` / `timestamp` |
| Sysmon EID 1 ile Security 4688'i ayrı iki süreç sanmak | Çift sayım | PID biçimi (hex/dec), alan şeması |
| PID'yi kimlik saymak | Yanlış parent | `ProcessGuid`, `ParentProcessGuid` |
| Chrome alt süreçlerini (`--type=`) parent sanmak | Yanlış cevap | `--type=` içermeyen ana süreç |
| Look-alike domain'leri aynı sanmak | Yanlış mail | Domain'i birebir karşılaştır |
| 503'lü isteği "ilk başarılı callback" saymak | Yanlış port/zaman | Status 2xx olanı seç |
| Görev adına bakıp rutin sanmak | Persistence'ı kaçırmak | Parent zinciri / lineage |
| Zone.Identifier `Contents` boş diye URL yok sanmak | Zinciri kesmek | URL'yi Suricata/web logdan al |
| Extraction'daki EID 2'yi timestomp sanmak | Yanlış alarm | Arşivden çıkarma bağlamına bak |

---

## 8. Kapsam (response scope) ve çıktı

Zinciri kanıtladıktan sonra bulgu **IOC** ve **kapsam sorularına** çevrilir.

**IOC tablosu doldur:**
- Domain'ler: lure / C2 birincil / C2 yedek; IP'ler
- Dosya: ZIP adı + SHA256, loader SHA256, kopya yolu, arşiv yolu
- Süreç: loader adı, parent kalıbı, UA
- Persistence: görev adı, çalıştırdığı komut
- Mail: gönderen domain, Message-ID, konu

**Kapsam sorguları (aynı IOC'yi filo genelinde ara):**
```spl
index=* "<lure-domain>" OR "<c2-domain>" OR "<backup-domain>"
| stats count values(sourcetype) as sources by host
```
```spl
index=* sourcetype="<WEB_ST>" user_agent="<UA>" | stats count min(_time) as first by client_ip
```
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1
| rex field=_raw "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| where sha256="<LOADER_SHA256>"
| stats count by host
```
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1 Image="*\\schtasks.exe" CommandLine="*<görev_adı>*"
| stats count by host
```
**Sorular:** Başka kullanıcılara aynı mail ulaştı mı? Başka kim tıkladı/indirdi? Arşiv hangi sunucuya yazıldı ve **o dosyaya başka kim erişti** (samba audit)? Hesap/yetki kapsamı ne? Sonraki hareket (lateral movement, 4624 logon tipleri)?

**Containment önerileri (kapsamdan sonra, bulguya göre):** Host izolasyonu, domain/IP blokajı, mail geri çekme (purge), görevi ve kopya dosyaları kaldırma, parola sıfırlama, paylaşımdaki arşivi adli kopyayla alıp kaldırma, tespit kuralı yazma (UA, URI kalıbı, `schtasks` parent'ı, zip-içi-exe deseni).

---

## 9. Kontrol listesi (kopyala-kullan)

**Hazırlık**
- [ ] `stats count by index, sourcetype` ile envanter
- [ ] Her sourcetype'ta ham olay (`_raw`) ve alan adı kontrolü
- [ ] Host ↔ IP eşlemesi; zaman damgası türleri notu
- [ ] Zaman aralığı: All time (daraltma sonra)

**Zincir**
- [ ] Çapa: EID 1'de arşiv-içi exe / alarm exe; ParentImage, ProcessGuid, hash
- [ ] İndirme: EID 15/11 (Chrome), Suricata http + fileinfo, referer
- [ ] Mail: rfc822 (domain) → postfix (Message-ID, status) → aday eleme
- [ ] Tarayıcıyı başlatan süreç (`--type=` yok)
- [ ] Loader çocukları, kopya, hash pivotu
- [ ] Persistence: schtasks `/TN`, lineage; 4698 / 106 / registry ile teyit
- [ ] C2: UA, URI, aralık, ilk 2xx; EID 1 `UtcTime` ile gecikme
- [ ] Failover: 503, DNS response A, µs farkı
- [ ] Akış eşleşmesi: SourcePort + DestAddress + Application
- [ ] Staging: Compress-Archive, parent, EID 11 ilk oluşturma
- [ ] SMB: CREATE → WRITE (SUCCESS), dest_ip, tree_id; samba audit teyidi

**Kapanış**
- [ ] Her halka ≥2 kaynakta doğrulandı mı?
- [ ] Zaman hesapları kesirli yapılıp biçim isteğine göre yuvarlandı mı?
- [ ] IOC tablosu + kapsam sorguları çalıştırıldı mı?
- [ ] Bulgu / çıkarım ayrımı yazıldı mı? ("kanıtlı" vs "muhtemel")

---

## 10. Anonim örnek zaman çizelgesi

Değerler uydurmadır; **sıra ve kaynak eşleşmesi** önemlidir.

| Göreli zaman | Olay | Kaynak |
|---|---|---|
| T0 | `jdoe`'ya `lure-review.example`'dan mail teslim edildi (`status=sent`) | rfc822 + postfix |
| T0 + dakikalar | Landing sayfası ve ardından `/downloads/Update.zip` (referer = landing sayfa) | web log + Suricata http |
| indirme anı | Chrome `Update.zip`'i kaydediyor (Zone.Identifier ADS, hash `H_zip`) | Sysmon EID 15 |
| +birkaç sn | Explorer ZIP'i `Temp\1\Temp1_Update.zip\loader.exe` altına açıyor (hash `H_exe`) | Sysmon EID 2/11/15 |
| +1-2 sn | `loader.exe` çalışıyor (parent `explorer.exe`) | Sysmon EID 1 |
| +~1 sn | `rundll32`, `schtasks` çocukları; `AppData\Local\<Sync>\<Sync>.exe` yazılıyor (aynı `H_exe`) | Sysmon EID 1/15 |
| +~1 sn | `<Sync>.exe` başlıyor (parent `loader.exe`) | Sysmon EID 1 |
| +onlarca sn | İlk `GET /sync/v4/check?...` → `204` (UA `<App>/4.1`) | web log + Suricata + WFP 5156 (aynı src port) |
| düzenli aralık | Aynı istek tekrarı (birkaç dk aralık) | web log |
| bir aralıkta | Birincil C2 `503` → ms içinde yedek domain DNS A cevabı → istek yedek domain'e | Suricata dns/http + web log |
| hemen ardından | `powershell` `Compress-Archive` (parent `<Sync>.exe`) → arşiv yazıldı | Sysmon EID 1 + 11 (+4688) |
| +onlarca sn | Arşiv dosya sunucusuna SMB2 CREATE → WRITE (SUCCESS) | Suricata smb |

---

## 11. Limitler ve dikkat

- **Kapsam telemetriye bağlıdır:** Sysmon yapılandırması, 5156 audit politikası, komut satırı denetimi, ADS `Contents` yakalama açık değilse ilgili halka görünmez; "yok" ≠ "olmadı".
- **Zaman tutarsızlığı:** Kaynaklar arası saat kayması olabilir (NTP). Karşılaştırmadan önce bir referans olayla (aynı bağlantı iki kaynakta) kayma ölç.
- **Saldırgan kontrollü alanlar** (UA, dosya adı, görev adı, mail başlıkları) güvenilmezdir; kararı olay yapısı (parent, hash, akış) belirlesin.
- **Çıkarım ile kanıtı ayır:** "Failover implant'a gömülü" gibi sonuçlar çıkarımdır; raporda öyle yaz.
- Bellek analizi gerekirse: [Volatility Memory Forensics Cheatsheet](../Volatility%20Memory%20Forensics%20Cheatsheet.md).

---
**Up:** [SOC Investigations - Index](SOC%20Investigations%20-%20Index.md)
**Related:** [Splunk SPL Patterns for IR](Splunk%20SPL%20Patterns%20for%20IR.md) · [Sysmon and Windows Event ID Guide](Sysmon%20and%20Windows%20Event%20ID%20Guide.md) · [Cross-Source Correlation](Cross-Source%20Correlation.md) · [Volatility Memory Forensics Cheatsheet](../Volatility%20Memory%20Forensics%20Cheatsheet.md) · [SCHtask](../Windows%20persistence/SCHtask.md)
