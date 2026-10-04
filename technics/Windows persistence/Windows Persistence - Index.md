---
title: "Windows Persistence — Index"
date: 2026-10-04
tags: [moc, index, windows, persistence]
---
# Windows Persistence — Index

Windows yerel kalıcılık (local persistence) tekniklerinin tamamı. Hepsi aynı fikrin farklı "yuvaları"dır: bir tetikleyiciye (boot, logon, task, uygulama olayı) backdoor bağlamak. Aşağıdaki sıra, kolaydan sinsiye doğru mantıklı bir öğrenme/uygulama akışıdır.

1. [Windows Local Persistence](Windows%20Local%20Persistence.md): Genel bakış — yetkisiz hesapları kurcalama, grup üyeliği ve LocalAccountTokenFilterPolicy.
2. [Using Windows Services](Using%20Windows%20Services.md): Yeni servis oluşturma veya mevcut servisi değiştirme (`exe-service`, `LocalSystem`).
3. [SCHtask](SCHtask.md): Zamanlanmış görevlerle periyodik backdoor + SD silerek görevi gizleme.
4. [Logon Based Persistence](Logon%20Based%20Persistence.md): Startup klasörü, Run/RunOnce, Winlogon, logon script'leri.
5. [Backdooring Existing Services](Backdooring%20Existing%20Services.md): Windows dışı servisleri silah yapma — web shell ve MSSQL trigger.
6. [Executable & Shortcut File Hijacking](Executable%20%26%20Shortcut%20File%20Hijacking.md): Exe backdoor'lama, .lnk hijack, dosya ilişkilendirme (file association) hijack.
7. [Login Screen Backdooring](Login%20Screen%20Backdooring.md): Sticky Keys / Utilman ile giriş ekranından parolasız SYSTEM shell.
8. [Security Descriptor](Security%20Descriptor.md): Doğrudan privilege atama (SeBackup/SeRestore) + WinRM security descriptor manipülasyonu.
9. [RID hijacking](RID%20hijacking.md): SAM'da RID değiştirerek yetkisiz hesabı Administrator'a eşitleme.

**Up:** [Home](../Home.md)
