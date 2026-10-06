---
title: "CTF Methodologies — Home"
date: 2026-10-06
tags: [moc, index, home]
---
# CTF Methodologies — Home

Bu vault'un giriş noktası. Her not buradan en fazla iki adımda erişilebilir. Graph view'da bu not merkezi hub'dır.

## Metodoloji & Checklist
- [Active Directory](Active%20Directory.md): AD ağlarında baştan sona saldırı checklist'i (recon → enum → foothold → privesc → lateral).
- [linux Privesc basic adımları](linux%20Privesc%20basic%20ad%C4%B1mlar%C4%B1.md): Linux'ta shell sonrası temel yetki yükseltme kontrolleri (SUID/SGID, sudo, cron).
- [Chrome Parola Çıkarma - DPAPI](Chrome%20Parola%20%C3%87%C4%B1karma%20-%20DPAPI.md): Chrome kayıtlı parolalarını DPAPI zinciriyle çözme cheatsheet'i (Local State → master key → AES-GCM; THM/canlı/MS hesabı senaryoları, v20 App-Bound).

## Networking & Temeller
- [DNS Nasıl Çalışır - 5 Aşama](DNS%20Nas%C4%B1l%20%C3%87al%C4%B1%C5%9F%C4%B1r%20-%205%20A%C5%9Fama.md): Ad çözümlemenin uçtan uca işleyişi — stub resolver, recursive resolver, iteratif root→TLD→authoritative yolculuğu, TTL/cache, ve DNS başarısızken LLMNR/NBT-NS/mDNS fallback + Responder/poisoning güvenlik köşeleri.

## Web Güvenliği
- [File Inclusion - Path Traversal](WEB/File%20Inclusion%20-%20Path%20Traversal.md): LFI/RFI ve path traversal için kapsamlı CTF cheatsheet (bypass, PHP wrapper, LFI→RCE).
- [Path traversal saldırılarında karşılaşılan zorluklar.](WEB/Path%20traversal%20sald%C4%B1r%C4%B1lar%C4%B1nda%20kar%C5%9F%C4%B1la%C5%9F%C4%B1lan%20zorluklar..md): Path traversal'da filtre atlatma ve absolute-path bypass notları.

## Windows Persistence
- [Windows Persistence - Index](Windows%20persistence/Windows%20Persistence%20-%20Index.md): Windows kalıcılık tekniklerinin tamamı — öğrenme sırasına göre dizilmiş alt-index.

## Write-Ups
- [THM-Ra-Writeup](THM-WriteUps/THM-Ra-Writeup.md): TryHackMe "Ra" (Windows/AD DC) — şifre sıfırlama bypass → Spark CVE-2020-12772 → NTLM hash → privesc.

## Referans
- [regex](regex.md): Regex hızlı referansı (escape, karakter sınıfları, aralıklar).

## Meta
- [_AI-CONTEXT](_AI-CONTEXT.md): AI ajanı için brifing — vault yapısı, yazım/bağlantı kuralları ve yeni not ekleme akışı. Yeni bir göreve başlamadan önce bununla Home okunur.
