---
title: "Special Privileges & Security Descriptors"
date: 2026-10-03
tags: [windows, persistence, privileges, winrm]
---
# Special Privileges & Security Descriptors

Persistence: Special Privileges & Security Descriptors — teknik akış:

1. **Temel prensip.** Windows'ta bir hesabın neyi yapabileceğini belirleyen şey grup üyeliği değil, hesaba atanmış **privilege**'lardır. Gruplar yalnızca bu privilege'ları toplu şekilde taşıdıkları için "ayrıcalıklı" görünür. Dolayısıyla aynı yetkiler, grup üyeliği olmadan doğrudan hesaba atanabilir. Bu, tespitten kaçınmanın temelini oluşturur: denetimler genelde grup üyeliklerine bakar, privilege atamalarına değil.
2. **Hedef privilege'lar.** `SeBackupPrivilege` ve `SeRestorePrivilege`. Bunlar yedekleme amacıyla tasarlanmıştır ve kritik bir özellik taşır: dosya/dizin üzerindeki **DACL'leri (erişim kontrol listelerini) tamamen yok sayarlar**. SeBackup, sistemdeki herhangi bir nesneyi okuma; SeRestore ise herhangi bir nesneye yazma yetkisi verir — nesnenin sahibi veya izinleri ne olursa olsun. Bu ikisi, Backup Operators grubunun sağladığı yeteneğin birebir karşılığıdır.
3. **Privilege ataması (`secedit`).** Yerel güvenlik politikası `secedit /export` ile `.inf` formatında dışa aktarılır. İlgili privilege satırlarına (`SeBackupPrivilege`, `SeRestorePrivilege`) hedef hesabın SID'i/adı eklenir. Değiştirilmiş politika `.sdb` veritabanına derlenip `secedit /configure` ile sisteme geri yüklenir. Bu noktada hesap, hiçbir ayrıcalıklı gruba üye olmadan Backup Operator yetkilerine sahiptir.
4. **WinRM erişimi — security descriptor manipülasyonu.** Privilege atandı ama hesabın uzaktan WinRM ile bağlanma hakkı yok. Bunu `Remote Management Users` grubuna ekleyerek çözmek iz bırakır. Bunun yerine, WinRM PowerShell session endpoint'inin kendi **security descriptor**'ı (SDDL formatında tutulan, servise uygulanan bir ACL) düzenlenir. `Set-PSSessionConfiguration -showSecurityDescriptorUI` ile hedef hesaba bu endpoint üzerinde bağlanma (Invoke/connect) izni verilir. Artık hesap WinRM'e erişebilir, ama bu izin bir grup üyeliği olarak değil, servisin kendi ACL'inde gömülü durur.
5. **Token kısıtlaması — `LocalAccountTokenFilterPolicy`.** Yerel bir hesap uzaktan bağlandığında UAC token filtrelemesi devreye girer ve atanmış privilege'lar token'dan düşürülür. Bu yüzden privilege'ların uzaktan oturumda etkili olabilmesi için `LocalAccountTokenFilterPolicy = 1` olmalıdır. (Bu değişiklik akışın önceki aşamasında zaten yapılmıştı.)
6. **Yetki yükseltme zinciri.** WinRM bağlantısı + SeBackup/SeRestore ile hesap, korumalı `SAM` ve `SYSTEM` registry hive'larını (normalde SYSTEM dışı hiçbir hesabın okuyamayacağı dosyaları) okuyabilir. Bu hive'lar `reg save` ile dışa alınır, offline olarak `secretsdump` ile işlenir ve yerel Administrator'ın NT hash'i elde edilir. Hash, Pass-the-Hash ile Administrator oturumu açmak için kullanılır.
7. **Gizlilik / tespit yüzeyi.** `net user <hesap>` çıktısı hesabı yalnızca `Users` grubunda gösterir — görünürde tamamen sıradan bir kullanıcı. Anomali yalnızca iki yerde gömülüdür: hesaba doğrudan atanmış hassas privilege'lar (`whoami /priv` veya yerel politika denetimiyle görülür) ve değiştirilmiş WinRM security descriptor'ı (SDDL incelemesiyle görülür). Grup tabanlı izlemeye dayanan savunmalar bu tekniği kaçırır; tespit için privilege atamalarının ve servis ACL'lerinin denetlenmesi gerekir.

---

**Up:** [Windows Persistence - Index](Windows%20Persistence%20-%20Index.md)
**Related:** [Login Screen Backdooring](Login%20Screen%20Backdooring.md) · [RID hijacking](RID%20hijacking.md)
