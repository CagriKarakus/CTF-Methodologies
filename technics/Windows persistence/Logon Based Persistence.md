
**Temel mantık**

Bu dört tekniğin ortak fikri şu: payload'ı, **kullanıcı sisteme her giriş yaptığında (logon)** otomatik çalışacak bir mekanizmaya bağlamak. Hepsi aynı tetikleyiciyi (logon) kullanır ama farklı yerlere yerleşir — bir savunmacı birini bulsa bile diğerleri ayakta kalabilir. Önemli bir ayrım hepsinde tekrar eder: değişiklik **kullanıcı bazında (HKCU / kişisel klasör)** mı yoksa **makine genelinde (HKLM / ortak klasör)** mi yapılıyor.

Çoğu teknikte akış aynı: msfvenom ile reverse shell üret → hedefe aktar (Python `http.server` + `wget`/`move`) → ilgili mekanizmaya bağla → oturumu kapatıp yeniden gir → shell düşer.

> Not: Her teknikte oturumu **Start menüsünden "Sign out"** ile kapatmak gerekir — RDP penceresini kapatmak yetmez, çünkü oturum arkada açık kalır ve logon tetiklenmez.

---

#### 1. Startup Folder (başlangıç klasörü)

**Mantık:** Windows, belirli bir klasöre konan executable'ları kullanıcı giriş yaptığında otomatik çalıştırır. Payload'ı oraya bırakmak tek başına kalıcılık sağlar — registry'ye dokunmaya bile gerek yok.

**İki kapsam:**

- **Tek kullanıcı:** `C:\Users\<kullanıcı>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` → sadece o kullanıcı giriş yapınca çalışır.
- **Tüm kullanıcılar:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` → makinedeki **herhangi** bir kullanıcı giriş yapınca çalışır (daha geniş kapsam, admin gerektirir).

**Payload formatı:** Burada normal `-f exe` yeterli (servislerdeki gibi `exe-service` gerekmez), çünkü doğrudan bir kullanıcı oturumunda çalışır.

cmd

```cmd
copy revshell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\"
```

---

#### 2. Run / RunOnce (registry ile logon'da çalıştırma)

**Mantık:** Payload'ı bir klasöre koymak yerine, registry'de "giriş sırasında şunu çalıştır" kaydı oluşturursun.

**Dört anahtar:**

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

**İki eksen:**

- **HKCU vs HKLM:** HKCU → sadece mevcut kullanıcı; HKLM → herkes.
- **Run vs RunOnce:** `Run` → her girişte tekrar tekrar çalışır (kalıcılık için ideal); `RunOnce` → yalnızca **bir kez** çalışıp kendini siler.

**Uygulama:** Payload'ı sabit bir yere taşı (`move revshell.exe C:\Windows`), sonra ilgili Run anahtarı altına bir **REG_EXPAND_SZ** değeri ekle. Değerin **adı** serbest (labda `MyBackdoor` olmalı), **verisi** çalıştırılacak komuttur. Giriş yapınca ~10-20 saniyede shell düşer.

---

#### 3. Winlogon

**Mantık:** Winlogon, kimlik doğrulamadan hemen sonra kullanıcı profilini yükleyen Windows bileşenidir. Hangi programları çalıştıracağı registry'de tanımlıdır; buraya payload eklersen logon zincirine sızarsın.

**İlgili anahtarlar** (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\`):

- **`Userinit`** → `userinit.exe`'ye işaret eder (kullanıcı profil tercihlerini geri yükler).
- **`shell`** → sistemin kabuğuna işaret eder (genelde `explorer.exe`).

**Kritik incelik:** Bu değerleri payload ile **değiştir**irsen (replace) logon zincirini bozarsın — `explorer.exe` ya da profil yüklenmez, sistem kullanılamaz hale gelir, dikkat çeker. Bunun yerine mevcut değeri **koruyup virgülle payload eklersin**. Winlogon virgülle ayrılmış komutların hepsini sırayla işler:

```
Userinit = C:\Windows\system32\userinit.exe, C:\Windows\revshell.exe
```

Böylece hem orijinal işlev korunur hem backdoor çalışır. (Labda `Userinit` kullanılması gerekiyor, ama `shell` ile de aynı mantık geçerli.)

---

#### 4. Logon Scripts (UserInitMprLogonScript)

**Mantık:** `userinit.exe` profil yüklerken `UserInitMprLogonScript` adlı bir ortam değişkenini (environment variable) kontrol eder. Bu değişken **varsayılan olarak tanımlı değildir** — yani sen onu yaratıp istediğin script'e/payload'a yönlendirebilirsin. Tanımlıysa, logon'da o script çalışır.

**Nerede:** `HKCU\Environment` altında `UserInitMprLogonScript` değeri oluşturulur, payload'a işaret ettirilir.

**Önemli kısıt:** Ortam değişkenleri **kullanıcıya özeldir** ve bu anahtarın **HKLM karşılığı yoktur**. Yani backdoor yalnızca o kullanıcıyı etkiler; her kullanıcı için ayrı ayrı kurman gerekir.

---

#### Karşılaştırma tablosu

|Teknik|Konum|Kapsam (user/makine)|Payload formatı|
|---|---|---|---|
|Startup folder|Dosya sistemi (klasör)|Her ikisi (iki ayrı klasör)|exe|
|Run / RunOnce|Registry (Run anahtarları)|HKCU=user, HKLM=makine|exe + REG_EXPAND_SZ|
|Winlogon|Registry (Winlogon)|Makine (HKLM)|exe (virgülle ekle)|
|Logon script|Registry (HKCU\Environment)|Sadece user (HKLM yok)|exe|

---

#### Ortak noktalar ve tespit yüzeyi

- **Tetikleyici hep logon:** Dördü de kullanıcı girişinde çalışır; bu yüzden shell'i almak için oturumu gerçekten kapatıp (Sign out) yeniden girmek şart.
- **User vs machine seçimi:** HKCU/kişisel klasör kurulumları admin gerektirmez ama tek kullanıcıyı etkiler; HKLM/ortak kurulumlar admin ister ama herkesi kapsar — hedefe göre seçilir.
- **Tespit için bakılacaklar:** Startup klasörlerindeki beklenmedik exe'ler; Run/RunOnce anahtarlarındaki şüpheli kayıtlar (bunlar en çok izlenen autorun konumlarıdır — Autoruns/Sysinternals bunları tarar); Winlogon `Userinit`/`shell` değerlerinde `userinit.exe`/`explorer.exe` dışında eklenmiş komutlar; `HKCU\Environment` altındaki `UserInitMprLogonScript` varlığı (normalde hiç olmaması gereken bir değişken, güçlü IOC). Ayrıca logon'la çakışan beklenmedik ağ bağlantıları.

Özetle bu dört teknik, aynı "logon'da tetikle" fikrinin dört ayrı yuvasıdır: dosya sistemi (Startup), klasik autorun registry'si (Run), logon bileşeni (Winlogon) ve kullanıcı ortam değişkeni (logon script). Çeşitlilik hem yedeklilik (biri temizlense diğeri kalır) hem de kapsam esnekliği (user/makine) sağlar.