---
title: "_AI-CONTEXT — Ajan Brifingi"
date: 2026-10-04
tags: [meta, ai-context, instructions]
---
# _AI-CONTEXT — Ajan Brifingi

> Bu dosya, bir AI ajanının (Claude) bu Obsidian vault'unda çalışırken **tüm notları okumadan** bağlamı kavraması içindir. Yeni bir göreve başlarken **önce bu dosyayı, sonra [Home](Home.md)'u** oku; bu ikisi tüm yapıyı ve kuralları verir. Tek tek notları yalnızca o notu düzenleyeceksen aç.

## Vault nedir
Sahibinin adı Çağrı. Bu, bir **siber güvenlik / CTF metodoloji** vault'u. Amaç: teknik, saldırı akışı ve write-up notlarını birbirine bağlı, graph'te gezilebilir bir bilgi ağı olarak tutmak.

- **Vault kökü (Obsidian):** `technics/` klasörü (`.obsidian/` buradadır).
- **Git kökü:** bir üst klasör, `CTF-Methodologies/`.
- Notlar Türkçe + İngilizce karışık yazılır (bu normaldir, koru).

## Yapı (taksonomi)
- `Home.md` — **ana MOC / manifest.** Her notun bir satırlık açıklamasıyla listesi burada. Vault'un canlı haritası budur; yeni not eklenince **burası güncellenir**.
- `WEB/` — web güvenliği notları (LFI, path traversal, …).
- `Windows persistence/` — Windows kalıcılık teknikleri. Kendi alt-index'i var: `Windows Persistence - Index.md` (öğrenme sırasına dizili).
- `THM-WriteUps/` — TryHackMe / platform write-up'ları.
- Kök seviye — tek başına duran metodoloji/referans notları (Active Directory checklist, linux privesc, regex).

## Yazım & bağlantı kuralları (yeni/düzenlenen her notta uygula)
1. **Frontmatter zorunlu:**
   ```yaml
   ---
   title: "Not Başlığı"
   date: YYYY-MM-DD
   tags: [konu, alt-konu]
   ---
   ```
2. Frontmatter'dan sonra aynı metinle bir `# H1` başlık.
3. **Bağlantılar relative markdown link, URL-encoded** — wikilink değil. Örn: `[Active Directory](Active%20Directory.md)`, alt klasörden `[Home](../Home.md)`. Sebep: vault git repo'su; bu format Obsidian + GitHub + VS Code'da çalışır.
4. Her not **footer** ile biter:
   ```
   ---
   **Up:** [üst index](path)
   **Related:** [komşu not](path) · [komşu not](path)
   ```
   `Related` = anlamlı komşular (önceki/sonraki teknik, üzerine kurulan/çelişen konu). Orphan (bağlantısız) not bırakma.
5. Tag'ler konu kümelerini oluşturur; mevcut tag'lerle tutarlı ol (`windows`, `persistence`, `web`, `lfi`, `active-directory`, `writeup`, `cheatsheet`, `methodology`, …).

## Yeni not ekleme akışı
1. Doğru klasöre koy (yoksa taksonomiye uygun yeni klasör + alt-index).
2. Frontmatter + H1 + içerik + Up/Related footer ekle.
3. İlgili notlara da karşılıklı `Related` bağlantısı ekle (tek yönlü bırakma).
4. **`Home.md`'ye** (ve varsa klasör index'ine) bir satırlık girdi ekle.
5. Bitince lint ile doğrula — kopuk link / orphan kalmamalı.

## Doğrulama (lint)
`obsidian-notes` becerisi mevcutsa onun `vault_lint.py` scripti ile `CTF-Methodologies` kökünü denetle: broken md links = 0, orphans = 0 hedeflenir. "folders without index" uyarısı WEB/THM-WriteUps için normaldir (Home bunları doğrudan listeler).

## Dokunma
- `.obsidian/` — makineye özel ayarlar, commit etme / değiştirme.
- Mevcut içeriği gereksiz yere yeniden yazma; yapı (frontmatter/başlık/bağlantı) ekle, teknik içeriği koru. Eksik bilgi varsa **uydurma**, sahibine sor.

**Up:** [Home](Home.md)
