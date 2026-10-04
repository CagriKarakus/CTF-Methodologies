---
title: "Login Screen Backdooring (Sticky Keys / Utilman)"
date: 2026-10-03
tags: [windows, persistence, accessibility, system]
---
# Login Screen Backdooring (Sticky Keys / Utilman)

**Temel mantık**

Bu iki teknik, önceki hepsinden farklı bir noktaya basar: **geçerli kimlik bilgisine (parola) hiç ihtiyaç duymadan**, kilit/giriş ekranından doğrudan terminal açmak. Fikir şu — Windows'un giriş ekranında, henüz kimse giriş yapmamışken bile çalışabilen bazı **erişilebilirlik (accessibility) özellikleri** vardır. Bu özellikleri tetikleyen binary'leri `cmd.exe` ile değiştirirsek, giriş ekranından bir komut satırı açabiliriz. Üstelik bu terminal **SYSTEM yetkisiyle** gelir, çünkü o accessibility araçları logon öncesinde SYSTEM bağlamında çalışır.

Kritik ön koşul: fiziksel erişim ya da RDP gerekir (giriş ekranını görmen/tetiklemen lazım). Bu, "makineye tekrar dönüş" sağlayan bir persistence + bypass yöntemidir.

---

#### Neden işe yarıyor — ortak çekirdek

Her iki özellik de giriş ekranında, parola girilmeden önce belirli bir System32 binary'sini SYSTEM yetkisiyle çalıştırır:

- **Sticky Keys** → `C:\Windows\System32\sethc.exe`
- **Utilman (Ease of Access)** → `C:\Windows\System32\Utilman.exe`

Mantık: O binary'yi `cmd.exe`'nin bir kopyasıyla değiştirirsen, özelliği tetiklediğinde beklenen araç yerine **SYSTEM yetkili bir komut istemi** açılır.

---

#### Dosyayı değiştirmenin önündeki engel — sahiplik ve izin

System32 içindeki bu dosyalar korunur; doğrudan üzerine yazamazsın çünkü sahibi SYSTEM/TrustedInstaller'dır. O yüzden iki adımlı bir hazırlık gerekir (her iki teknikte de aynı):

1. **`takeown`** → dosyanın **sahipliğini** kendi kullanıcına al:

cmd

```cmd
   takeown /f c:\Windows\System32\sethc.exe
```

2. **`icacls ... /grant`** → kendine o dosya üzerinde **tam (F = Full) izin** ver:

cmd

```cmd
   icacls C:\Windows\System32\sethc.exe /grant Administrator:F
```

3. **`copy`** → `cmd.exe`'yi hedef binary'nin üzerine kopyala:

cmd

```cmd
   copy c:\Windows\System32\cmd.exe C:\Windows\System32\sethc.exe
```

Sahiplik + izin olmadan 3. adım "access denied" verir. Bu `takeown → icacls → copy` zinciri, Windows'ta korumalı sistem dosyalarını değiştirmenin standart yoludur.

---

#### Teknik 1 — Sticky Keys (sethc.exe)

**Tetikleyici:** Varsayılan olarak her Windows kurulumunda etkin olan bir kısayol — **SHIFT tuşuna 5 kez basmak** Sticky Keys'i tetikler ve `sethc.exe`'yi çalıştırır. (Sticky Keys normalde `CTRL+ALT+DEL` gibi kombinasyonları ardışık basmaya izin veren bir erişilebilirlik özelliğidir.)

**Uygulama:** `sethc.exe`'yi yukarıdaki zincirle `cmd.exe` kopyasıyla değiştir → oturumu kilitle (Start menü → Lock) → giriş ekranında **SHIFT'e 5 kez bas** → SYSTEM yetkili cmd açılır. Parola gerekmez.

---

#### Teknik 2 — Utilman (utilman.exe)

**Tetikleyici:** Giriş ekranındaki **"Ease of Access" (Erişim Kolaylığı) butonu**. Bu butona basınca `Utilman.exe` SYSTEM yetkisiyle çalışır.

**Uygulama:** Aynı `takeown → icacls → copy` zinciriyle `utilman.exe`'yi `cmd.exe` kopyasıyla değiştir → oturumu kilitle → giriş ekranında **Ease of Access butonuna tıkla** → SYSTEM yetkili cmd açılır.

İki teknik işlevsel olarak özdeştir; tek fark hedef binary ve tetikleme biçimidir (5x SHIFT vs ekrandaki buton).

---

#### Karşılaştırma

||Sticky Keys|Utilman|
|---|---|---|
|Hedef binary|`sethc.exe`|`Utilman.exe`|
|Tetikleme|SHIFT ×5|Ease of Access butonu|
|Yetki|SYSTEM|SYSTEM|
|Değiştirme yöntemi|takeown → icacls → copy|takeown → icacls → copy|

---

#### Önemli noktalar ve tespit yüzeyi

- **Parola gerektirmez, SYSTEM verir:** İki teknik de giriş ekranından, kimlik doğrulamadan önce, en yüksek yerel yetkiyle terminal açar — hem authentication bypass hem güçlü persistence.
- **Kalıcılık boyutu:** Değişiklik diskte kalıcı olduğu için, saldırgan makineye RDP/fiziksel erişimi olduğu sürece istediği an bu "arka kapıyı" kullanabilir.
- **Tespit için bakılacaklar:** `sethc.exe` / `utilman.exe` dosyalarının **boyut/hash anomalisi** (cmd.exe ile birebir aynı hale gelirler — bu çok bariz bir IOC'dir); bu dosyaların beklenmedik sahiplik/izin değişiklikleri; System32'de korumalı dosyalara yapılan `takeown`/`icacls` işlemleri (olay günlüklerinde iz bırakır). Savunma tarafında bu binary'lerin bütünlüğünü (file integrity monitoring) izlemek en etkili yöntemdir. Ayrıca bir karşı önlem olarak, kritik sunucularda accessibility shortcut'larının devre dışı bırakılması önerilir.

Özetle: giriş ekranında SYSTEM yetkisiyle çalışan iki erişilebilirlik binary'si (`sethc.exe`, `utilman.exe`) `cmd.exe` ile değiştirilir; ardından sahiplik/izin ayarlanıp dosya üzerine yazılır. Sonuç — parolasız, SYSTEM yetkili, giriş ekranından tetiklenen kalıcı bir arka kapı.

---

**Up:** [Windows Persistence - Index](Windows%20Persistence%20-%20Index.md)
**Related:** [Executable & Shortcut File Hijacking](Executable%20%26%20Shortcut%20File%20Hijacking.md) · [Security Descriptor](Security%20Descriptor.md)
