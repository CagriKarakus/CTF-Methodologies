---
title: "Windows Local Persistence — Genel Bakış"
date: 2026-10-03
tags: [windows, persistence, accounts]
---
# Windows Local Persistence — Genel Bakış

### Tampering with Unprivileged Accounts

Assign group membership ,

```
net localgroup administrator fakeuser /add
```

if this look too sus you can add it to "Backup Operators, Remote Management Users" groups also.
- The groups must be enabled.
- **LocalAccountTokenFilterPolicy** must be disabled. It weont allow you toget control over winrm. Sebebi **UAC (User Account Control)**. UAC'nin `LocalAccountTokenFilterPolicy` adlı bir özelliği var. Bu özellik, bir **yerel hesap** uzaktan (remote) giriş yaptığında o hesabın yönetici ayrıcalıklarını token'dan söküp atıyor.

Önemli ayrım şu:

- Grafik arayüzden (local session) bağlanırsan UAC üzerinden yetkini yükseltebilirsin (elevate).
- Ama WinRM ile bağlanıyorsan, kısıtlı (limited) bir access token'a mahkumsun — yönetici ayrıcalığın hiç yok.

- birden fazla düşük profilli kullanıcı hesabına Administrator ile aynı parolayı verirsin; biri fark edilip kapatılsa bile diğerleri aynı yetkiyle elinde kalır, hepsi aynı hash'le pass-the-hash yapılabilir.


https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md

---

**Up:** [Windows Persistence - Index](Windows%20Persistence%20-%20Index.md)
**Related:** [Using Windows Services](Using%20Windows%20Services.md) · [Active Directory](../Active%20Directory.md) · [RID hijacking](RID%20hijacking.md)
