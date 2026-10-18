---
title: "Splunk SPL Patterns for IR"
date: 2026-10-18
tags: [incident-response, splunk, spl, cheatsheet, methodology]
---
# Splunk SPL Patterns for IR

> Olay incelemesinde tekrar tekrar kullanılan SPL kalıpları. Her kalıbın yanında **ne zaman**, **neden böyle yazılır** ve **tuzağı** var. Alan adları ortama göre değişir; önce [metodoloji notundaki](Phishing%20Kill%20Chain%20-%20Splunk%20Investigation%20Methodology.md) "ortamı tanı" adımını uygula. Placeholder'lar `<ANGLE_BRACKET>` ile yazılmıştır.

---

## 1. Keşif

```spl
| eventcount summarize=false index=* | dedup index | table index
```
Hangi index'ler var.

```spl
index=* | stats count min(_time) as first max(_time) as last by index, sourcetype
| convert ctime(first) ctime(last)
```
Hangi kaynak, kaç olay, hangi aralık. **Neden:** Küçük sourcetype (örn. ham mail) önce taranır; kapsama boşlukları (hangi gün log yok) görünür.

```spl
index=* sourcetype="<ST>" | head 3 | table _raw
index=* sourcetype="<ST>" | fieldsummary maxvals=5 | table field count distinct_count values
```
Ham olay ve alan envanteri. **Tuzak:** Tablodaki boş sütun = alan o adla yok demektir, olay yok demek değil.

---

## 2. Kaynak ayırma

```spl
index=* "<anahtar>" NOT EventCode=*
```
Windows olaylarının hepsinde `EventCode` vardır; bunu dışlamak geriye web, mail, ağ loglarını bırakır. **Ne zaman:** bir dosya adı/domain'in ağ ve mail tarafında nerede geçtiğini görmek için.

```spl
index=* "<anahtar>" NOT sourcetype="<WEB_ST>" NOT sourcetype="<SURICATA_ST>"
| stats count by sourcetype
```
Anahtarın hangi kaynaklarda geçtiğini sayarak keşif.

---

## 3. Alan çıkarma (rex)

**Sysmon Hashes → SHA256**
```spl
| rex field=_raw "Name=['\"]Hashes?['\"]>(?<hashes>[^<]*)"
| rex field=hashes "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
```
`Hashes` bir olayda birden fazla algoritmayı taşıyabilir (`MD5=..,SHA256=..`); `Hash` ismi EID 15'te geçer. İki ismi birden yakalayan `Hashes?` kullan.

**Zamanlanmış görev adı**
```spl
| rex field=CommandLine "(?i)/tn\s+\"?(?<task_name>[^\"/]+)"
```
**Tuzak:** Tırnaksız ve boşluklu görev adlarını keser; sonucu ham komut satırıyla karşılaştır.

**Postfix queue id, Message-ID, durum**
```spl
| rex "\]:\s(?<qid>[0-9A-Za-z]+):\s"
| rex "message-id=<(?<msgid>[^>]+)>"
| rex "from=<(?<mfrom>[^>]*)>"
| rex "to=<(?<rcpt>[^>]*)>"
| rex "status=(?<status>\w+)"
| where isnotnull(qid) AND qid!="warning"
```
Queue id, bir mesajın tüm postfix satırlarını bağlar.

**Ham mail başlıkları (rfc822)**
```spl
| rex field=_raw "(?im)^From:\s*(?<hdr_from>.+)$"
| rex field=_raw "(?im)^Message-ID:\s*<(?<hdr_msgid>[^>]+)>"
| rex field=_raw "(?im)^Return-Path:\s*<(?<hdr_rp>[^>]*)>"
```
Message-ID'yi köşeli parantezsiz yakalamak için `<` `>` dışarıda bırakıldı.

---

## 4. Süreç soyağacı (lineage)

**Bir sürecin çocukları**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1 ParentProcessGuid="<GUID>"
| table _time UtcTime Image CommandLine ProcessGuid
```

**Bir sürecin ebeveyni**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1 ProcessGuid="<PARENT_GUID>"
| table _time Image CommandLine ParentImage ParentProcessGuid
```
Tekrarla (manuel pivot). **Neden GUID:** PID yeniden kullanılır; `ProcessGuid` benzersizdir.

**PID'nin önceki sahibi**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1 ProcessId=<PID>
| table _time UtcTime ProcessId Image ProcessGuid
| sort - UtcTime
```
Hedef sürecin kendi satırından bir alt satır, o PID'yi önce kullanan süreçtir. Parent ile karıştırma.

**Arşiv içinden çalıştırılan süreçler**
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1
  (Image="*.zip\\*" OR Image="*\\7zO*" OR Image="*\\Rar$DI*")
| table _time host User Image CommandLine ParentImage
```

---

## 5. Zaman: sıralama, aralık, fark

**Olay zamanına göre sırala (index zamanına değil)**
```spl
| sort 0 UtcTime
```
`sort 0` tüm sonuçları sıralar (varsayılan sort 10.000 ile sınırlıdır).

**Ardışık olaylar arası süre (beacon aralığı)**
```spl
| sort 0 _time
| streamstats current=f last(_time) as prev by server_name
| eval delta=round(_time-prev,1)
```
**Özet:**
```spl
| stats count avg(delta) as avg_s stdev(delta) as stdev_s by server_name
| eval jitter_ratio=round(stdev_s/avg_s,3)
```
Düşük `jitter_ratio` periyodik trafiktir. **Tuzak:** `streamstats` sıralamaya bağlıdır; her zaman önce `sort 0 _time`.

**İki zaman damgası farkı**
```spl
| makeresults
| eval t1=strptime("<YYYY-MM-DD HH:MM:SS.mmm>","%Y-%m-%d %H:%M:%S.%3N")
| eval t2=strptime("<YYYY-MM-DDTHH:MM:SS.uuuuuu+0000>","%Y-%m-%dT%H:%M:%S.%6N%z")
| eval diff_s=round(t2-t1,3)
| eval diff_ms=round((t2-t1)*1000,3)
| eval whole_floor=floor(t2-t1), whole_round=round(t2-t1,0)
```
`%3N` = ms, `%6N` = µs. Uç değerleri `_time`'dan değil, olay alanından yaz.

**Zaman penceresi sabitle**
```spl
index=* ... earliest="<MM/DD/YYYY:HH:MM:SS>" latest="<MM/DD/YYYY:HH:MM:SS>"
```
Biçim: `MM/DD/YYYY:HH:MM:SS`. Splunk kullanıcı saat dilimi ayarına göre yorumlar; UTC logları incelerken tarayıcı/hesap saat dilimini kontrol et.

---

## 6. Ağ ve akış

**Suricata HTTP**
```spl
index=* sourcetype="<SURICATA_ST>" event_type=http "<domain>"
| table timestamp src_ip src_port dest_ip dest_port http.hostname http.url http.status http.http_user_agent http.http_refer
```

**Suricata DNS (EVE v2)**
```spl
index=* sourcetype="<SURICATA_ST>" event_type=dns "<domain>"
| table timestamp dns.type dns.rrname dns.answers{}.rrtype dns.answers{}.rdata
| sort 0 timestamp
```
`dns.type=response` cevap, `request` sorgudur. Eski EVE'de `answer`/`query` ve `dns.rrtype`/`dns.rdata`.

**Suricata fileinfo (dosya transferi tamamlandı mı)**
```spl
index=* sourcetype="<SURICATA_ST>" event_type=fileinfo "<dosya_adı>"
| table timestamp src_ip dest_ip fileinfo.filename fileinfo.size fileinfo.state flow_id
```

**Suricata SMB**
```spl
index=* sourcetype="<SURICATA_ST>" event_type=smb "<dosya_adı>"
| table timestamp src_ip dest_ip smb.command smb.status smb.filename smb.share
| sort 0 timestamp
```
Paylaşım adı için aynı `flow_id` / `tree_id` ile `SMB2_COMMAND_TREE_CONNECT` olayını ara.

**WFP bağlantısı (5156) ↔ Suricata eşleştirme**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=5156 Application="*<implant>*"
| table _time Application SourceAddress SourcePort DestAddress DestPort Direction
```
Eşleşme koşulu: `SourcePort = src_port` ve `DestAddress = dest_ip`. `Application` kernel formatında (`\device\harddiskvolume1\...`).

**Domain'e hangi hostlar bağlandı**
```spl
index=* "<domain>" | stats count values(sourcetype) as sources by host
```
`host` alanı ağ kaynaklarında olmayabilir; `src_ip`/`client_ip` ile de dene.

---

## 7. Mail

**Domain'den gelen ham mailler**
```spl
index=* sourcetype="<RFC822_ST>" "<lure-domain>" | table _time _raw
```

**Message-ID'den teslim durumu**
```spl
index=* sourcetype="<POSTFIX_ST>"
| rex "\]:\s(?<qid>[0-9A-Za-z]+):\s"
| rex "message-id=<(?<msgid>[^>]+)>"
| rex "from=<(?<mfrom>[^>]*)>"
| rex "to=<(?<rcpt>[^>]*)>"
| rex "status=(?<status>\w+)"
| where isnotnull(qid) AND qid!="warning"
| stats min(_time) as first values(msgid) as msgid values(mfrom) as mfrom values(rcpt) as rcpt values(status) as status by qid
| search msgid="<MESSAGE_ID>"
```
**Neden stats by qid:** Message-ID, durum ve alıcı postfix'te *farklı satırlarda* durur; queue id ile birleşirler.

---

## 8. Windows / Sysmon

**Process creation özeti**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=1
| table _time UtcTime User Image CommandLine ParentImage ProcessGuid
| sort 0 UtcTime
```

**İndirilen dosya (Chrome, ADS)**
```spl
index=* sourcetype="<WINDOWS_ST>" host="<WS>" EventCode=15 Image="*chrome.exe"
| table _time UtcTime TargetFilename CreationUtcTime Hash Contents
```

**Persistence: schtasks**
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1 Image="*\\schtasks.exe"
| rex field=CommandLine "(?i)/tn\s+\"?(?<task_name>[^\"/]+)"
| table _time host ParentImage CommandLine task_name
```

**Registry: TaskCache**
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode IN (12,13,14) TargetObject="*\\Schedule\\TaskCache\\*"
| table _time host Image EventType TargetObject Details
```

**PowerShell arşivleme / staging**
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1 Image="*\\powershell.exe" CommandLine="*Compress-Archive*"
| table _time UtcTime ProcessId ProcessGuid ParentImage CommandLine
```

---

## 9. Hunting ve kapsam

**Aynı User-Agent'ı kullanan istemciler**
```spl
index=* sourcetype="<WEB_ST>" user_agent="<UA>"
| stats count min(_time) as first max(_time) as last by client_ip
| convert ctime(first) ctime(last)
```

**Aynı hash'i çalıştıran hostlar**
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1
| rex field=_raw "SHA256=(?<sha256>[A-Fa-f0-9]{64})"
| where sha256="<HASH>"
| stats count min(_time) as first by host
```

**Nadir domain (long tail)**
```spl
index=* sourcetype="<WEB_ST>"
| stats dc(client_ip) as hosts count by server_name
| sort hosts, count
```
Az sayıda host'un ziyaret ettiği domain'ler öne çıkar. Hunt başlangıcı olarak kullan, tek başına kanıt sayma.

**Aynı görev adı / komutu kullanan hostlar**
```spl
index=* sourcetype="<WINDOWS_ST>" EventCode=1 Image="*\\schtasks.exe" CommandLine="*<görev>*"
| stats count by host ParentImage
```

---

## 10. Hızlı hatırlatmalar

- Alan boş → `_raw`; sonra `rex`.
- Zaman farkı → olay alanı + aynı çözünürlük + önce kesirli, sonra yuvarla.
- PID değil GUID; ad değil lineage.
- request/response, CREATE/WRITE, 503/204, EID 1/4688: **kardeş olayları bilinçli ele**.
- `sort 0` ve `earliest/latest` kullanmayı unutma.

---
**Up:** [SOC Investigations - Index](SOC%20Investigations%20-%20Index.md)
**Related:** [Phishing Kill Chain - Splunk Investigation Methodology](Phishing%20Kill%20Chain%20-%20Splunk%20Investigation%20Methodology.md) · [Sysmon and Windows Event ID Guide](Sysmon%20and%20Windows%20Event%20ID%20Guide.md) · [Cross-Source Correlation](Cross-Source%20Correlation.md)
