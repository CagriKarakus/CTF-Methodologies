---
title: "SOC Investigations - Index"
date: 2026-10-18
tags: [moc, index, incident-response, soc, splunk]
---
# SOC Investigations - Index

SIEM (Splunk) üzerinde çok kaynaklı log ile olay inceleme notları. Makineye/odaya özel değil, **yöntem** odaklı: hangi soruyu hangi kaynağa, neden ve nasıl sorarım. Yeni bir vaka çözdükçe buraya, aynı yapıda ek notlar eklenir.

## Önerilen okuma sırası
1. [Phishing Kill Chain - Splunk Investigation Methodology](Phishing%20Kill%20Chain%20-%20Splunk%20Investigation%20Methodology.md): Ana metodoloji. Yaklaşım, kanıt zinciri, mail → indirme → execution → persistence → C2 → staging → exfil aşamalarında nereye/neden/nasıl bakılır, tuzaklar, kapsam ve kontrol listesi.
2. [Sysmon and Windows Event ID Guide](Sysmon%20and%20Windows%20Event%20ID%20Guide.md): Hangi olay neyi kanıtlar, hangi alan neyle karıştırılır (EID 1/11/15, 4688, 5156, 4698 ...).
3. [Cross-Source Correlation](Cross-Source%20Correlation.md): Kaynakları hangi ortak anahtarla birleştirirsin (5-tuple, flow_id, ProcessGuid, Message-ID, hash), kör noktalar ve güven seviyeleri.
4. [Splunk SPL Patterns for IR](Splunk%20SPL%20Patterns%20for%20IR.md): Tekrar kullanılabilir SPL kalıpları (keşif, rex, lineage, zaman farkı, ağ/mail/SMB, hunting).

## Ne zaman hangisi?
- **Yeni bir olayda nereden başlayacağım?** → Ana metodoloji, Bölüm 1.3 (giriş noktası → yön) ve Bölüm 2 (ortamı tanı).
- **Bir olay kaydı ne anlama geliyor?** → Sysmon and Windows Event ID Guide.
- **İki log kaynağı aynı olayı gösteriyor mu?** → Cross-Source Correlation.
- **Sorguyu nasıl yazarım?** → SPL Patterns.
- **Süre/zaman farkı sorusu** → Ana metodoloji Bölüm 5.
- **Bellek imajı gerekirse** → [Volatility Memory Forensics Cheatsheet](../Volatility%20Memory%20Forensics%20Cheatsheet.md).

---
**Up:** [Home](../Home.md)
**Related:** [Volatility Memory Forensics Cheatsheet](../Volatility%20Memory%20Forensics%20Cheatsheet.md)
