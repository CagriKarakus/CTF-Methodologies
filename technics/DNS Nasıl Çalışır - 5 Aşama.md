---
title: "DNS Nasıl Çalışır — 5 Aşamada Ad Çözümleme"
date: 2026-10-06
tags: [dns, networking, methodology, fundamentals]
---
# DNS Nasıl Çalışır — 5 Aşamada Ad Çözümleme

> Bir kullanıcı tarayıcısına bir adres yazdığı andan, o adresin bir IP'ye çevrilip bağlantının kurulduğu ana kadar geçen süreç. Örnek boyunca `example.example.com` adresini takip ediyoruz. Süreci beş aşamaya böldük: (1) kendi makinen, (2) recursive resolver, (3) iteratif yolculuk, (4) cevabın dönüşü ve cache'lenmesi, (5) DNS başarısız olunca devreye giren yerel fallback mekanizmaları.

## İki temel kavram (baştan oturtulması gerekenler)

DNS'in tamamı iki ayrımın üstüne kuruludur. Bunları baştan netleştirmek, geri kalan her şeyi kolaylaştırır:

- **Recursive sorgu vs iteratif sorgu.** Recursive = "bana tam cevabı getir, ara adımlarla uğraşmam". İstemci → resolver ilişkisi budur. İteratif = "tam cevabı bilmiyorsan, bir sonraki adımda kime sormam gerektiğini söyle". Resolver → root/TLD/authoritative ilişkisi budur.
- **Recursive resolver vs authoritative sunucu.** Recursive resolver senin için işi sonuna kadar takip eden aracıdır (DC, modem, `8.8.8.8`). Authoritative sunucu ise bir zone'un birinci elden sahibidir; recursion yapmaz, sadece kendi bildiğini söyler (root, TLD, domain'in NS'leri).

---

## AŞAMA 1: Kendi makinede olanlar (Stub Resolver)

Bilgisayardaki DNS istemcisine **stub resolver** denir. Kendisi internette dolaşmaz; önce yerel kaynaklara bakar, bulamazsa soruyu ağ ayarlarında tanımlı sunucuya iletir.

### 1.1 Tarayıcı daha DNS'e gelmeden

- **URL mi, arama mı?** Adres çubuğuna yazılan şeyin URL mi yoksa arama terimi mi olduğuna karar verilir.
- **Host ayıklanır.** `https://example.example.com:8443/login?x=1` adresinden DNS'e sadece `example.example.com` gider; şema, port ve path DNS'i ilgilendirmez.
- **Zaten IP mi?** `http://192.168.1.10` yazılırsa DNS sorgusu hiç yapılmaz.
- **Özel isimler.** `localhost` neredeyse her sistemde DNS'e gitmeden `127.0.0.1` / `::1` olur (RFC 6761).
- **Punycode.** Unicode karakterli domainler (`çağrı.com`) ASCII'ye çevrilir (`xn--...`). Bu dönüşüm homograph/phishing saldırılarında kullanılır (Kiril "а" ile sahte `аpple.com`).

### 1.2 Tarayıcı cache'i

Tarayıcılar her sayfa yüklemede onlarca isim çözer (CDN, font, analytics). Her seferinde OS'ye sormamak için kendi cache'lerini tutar.

- Chrome: `chrome://net-internals/#dns`
- Firefox: `about:networking#dns`

**DoH (DNS over HTTPS):** Tarayıcıda "Secure DNS" açıksa, sorgu OS'nin DNS ayarları atlanıp doğrudan HTTPS üzerinden bir DoH sunucusuna gider. Bu durumda kurumsal DNS sunucusu sorguyu hiç görmez; ağ trafiğinde UDP 53 yerine sıradan TCP 443 görürsün. Güvenlik tarafında bu önemli: zararlı yazılımlar DoH ile DNS loglarından kaçabilir, bu yüzden kurumlar tarayıcı DoH'unu kapatır veya bilinen DoH sunucularını engeller.

**DNS prefetch:** Tarayıcı, sayfadaki linklerin domainlerini kullanıcı tıklamadan önce çözebilir. Yani DNS loglarında hiç ziyaret edilmemiş domainler görünebilir — log analizinde yanlış alarmı önlemek için bilinmesi gerekir.

### 1.3 Tarayıcıdan işletim sistemine geçiş

Tarayıcı cache'te bulamazsa (ve DoH kullanmıyorsa), OS'nin ortak isim-çözme fonksiyonunu çağırır:

```c
getaddrinfo("example.example.com", ...)
```

Bu fonksiyon tüm programların (tarayıcı, `ping`, `curl`, SSH) kullandığı ortak kapıdır. Genelde **hem A (IPv4) hem AAAA (IPv6)** kaydı istenir — bu yüzden tek bir siteye girişte Wireshark'ta iki sorgu görülür. İki cevap da gelince **Happy Eyeballs** algoritmasıyla IPv4 ve IPv6 paralel denenir, hangisi önce bağlanırsa o kullanılır.

### 1.4 İşletim sisteminde cache ve hosts

**Windows** — isim çözümlemeyi **DNS Client servisi (Dnscache)** yönetir:
1. Kendi hostname'i mi? → doğrudan kendi IP'si
2. DNS Client cache'i (hosts dosyası kayıtları bu cache'e önceden yüklenir, yani cache ve hosts tek yerden kontrol edilir)
3. NRPT (Name Resolution Policy Table) — "şu domain için şu sunucu/DNSSEC" kuralları
4. Bulunamazsa → DNS sunucusuna sorgu (Aşama 2)
5. DNS başarısızsa → LLMNR / NetBIOS / mDNS (Aşama 5)

```powershell
ipconfig /displaydns          # cache içeriği
ipconfig /flushdns            # cache temizle
Get-DnsClientCache
Resolve-DnsName example.com   # tüm OS zincirini kullanarak çözümle
Get-DnsClientServerAddress    # hangi DNS sunucusu ayarlı
```

Hosts dosyası: `C:\Windows\System32\drivers\etc\hosts` (yazmak için admin gerekir).

**Linux** — merkezi bir servis zorunlu değildir; davranış `/etc/nsswitch.conf` ile belirlenir:
```
hosts: files mdns4_minimal [NOTFOUND=return] dns
```
Soldan sağa okunur: `files` → `/etc/hosts`, `mdns4_minimal` → `.local` için mDNS, `dns` → `/etc/resolv.conf`'taki sunucuya sorgu. glibc kendisi cache tutmaz; cache varsa onu ayrı bir servis sağlar (**systemd-resolved** `127.0.0.53`'te dinler, veya `nscd`/`dnsmasq`/`unbound`).

```bash
getent hosts example.com     # nsswitch zincirinin tamamını kullanır (hosts dahil)
resolvectl status            # gerçek upstream DNS sunucuları
resolvectl flush-caches
cat /etc/resolv.conf         # hangi sunucuya gidiliyor
```

**macOS** — **mDNSResponder** hem DNS cache'ini hem mDNS'i yönetir. `/etc/resolver/` ile domain bazlı yönlendirme yapılabilir. Temizleme:
```bash
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
```

### 1.5 Kritik tuzak: `dig` ve `nslookup` OS zincirini ATLAR

`dig` ve `nslookup` **hosts dosyasına bakmaz** ve **OS cache'ini kullanmaz**. Kendi DNS paketlerini oluşturup doğrudan DNS sunucusuna gönderirler. Dolayısıyla:

- `/etc/hosts`'a `1.2.3.4 test.local` yaz.
- `ping test.local` → 1.2.3.4'e gider (OS zinciri kullanılıyor).
- `nslookup test.local` → "bulunamadı" der (doğrudan DNS sunucusuna sordu).

Bir uygulamanın gerçekte hangi IP'yi göreceğini test etmek için `getent hosts` (Linux) / `Resolve-DnsName` (Windows) kullan. DNS sunucusunun ne cevapladığını görmek için `dig`/`nslookup` kullan. İkisi farklı soruların cevabıdır.

### 1.6 İsim tamamlama: suffix, search, ndots

Tek kelimelik bir isim (`fileserver`) yazıldığında sistem onu tamamlamaya çalışır.

- **Windows:** Primary DNS suffix (`fileserver` → `fileserver.corp.local`), suffix search list (GPO ile birden çok sonek), devolution.
- **Linux:** `/etc/resolv.conf` içindeki `search` satırı ve `ndots` ayarı. `ndots:N` = "isimde en az N nokta varsa önce olduğu gibi dene, yoksa önce sonekleri ekle". Kubernetes'te `ndots:5` varsayılandır ve pod içinden `api.github.com` sorgusunda önce birkaç gereksiz `...svc.cluster.local` sorgusu gider — klasik performans/gereksiz-trafik sebebi.
- **Sondaki nokta:** `example.com.` bir **FQDN**'dir; hiçbir sonek eklenmez. DNS'te her ismin sonunda görünmeyen bir nokta vardır ve **root**'u temsil eder.

### 1.7 Dışarıya çıkan ilk paket

Yerelde hiçbir şey bulunamazsa stub resolver bir sorgu paketi oluşturur:

| Alan | Değer | Açıklama |
|---|---|---|
| Hedef | Ayarlı DNS sunucusu | DC IP'si / `192.168.1.1` / `8.8.8.8` |
| Protokol / port | UDP / 53 | Cevap büyükse TCP'ye geçilir |
| Kaynak port | Rastgele | Cache poisoning'i zorlaştırmak için (Aşama 2) |
| Transaction ID | Rastgele 16 bit | Cevabı sorguyla eşleştirmek için |
| RD biti | 1 | "Benim için recursive olarak çöz" |
| Soru | `example.example.com`, tip A, sınıf IN | |

---

## AŞAMA 2: Recursive Resolver

Paket, `resolv.conf`'ta yazan sunucuya ulaştı. Buradaki yazılıma **recursive resolver** (caching resolver) denir. Kim olduğu ağ ayarına bağlıdır: AD ortamında Domain Controller, evde modem (genelde ISS'ye ileten bir forwarder gibi davranır), elle ayarlıysa `8.8.8.8` / `1.1.1.1` / `9.9.9.9`.

### 2.1 Resolver sorguyu aldığında yaptığı kontroller

**Adım A — Erişim kontrolü (bu sorgu bana izinli mi?).** Resolver önce "bu istemciye hizmet veriyor muyum?" diye bakar. Değilse `REFUSED` döner. `REFUSED`, "isim yok" demek değildir; "bu sorguyu işlemeyi reddediyorum" demektir. Teşhiste RCODE'ları ayırmak kritiktir:

- `NXDOMAIN` → sunucu çalıştı, sordu, isim gerçekten yok
- `REFUSED` → sunucu sorguyu hiç işlemedi (yetki yok, recursion kapalı, upstream yok)
- `SERVFAIL` → işlemeye çalıştı ama patladı (DNSSEC tutmadı, upstream cevapsız, lame delegation)

**Adım B — Ben bu zone'un sahibi miyim?** Sorulan isim resolver'ın barındırdığı bir **zone**'a aitse (örneğin AD DC'nin `corp.local`'ı), cevap doğrudan kendi verisinden verilir, dışarı çıkılmaz. Bu cevap **authoritative**'dir (`AA` biti = 1). İç ağ isimlerinin ışık hızında çözülmesinin sebebi budur.

**Adım C — Cache'imde var mı?** Zone sahibi değilse cache'e bakılır. TTL dolmadıysa cevap cache'ten döner; bu cevap **non-authoritative**'dir (`AA` = 0).
- **Pozitif cache:** "example.com = 93.184.x.x", kaydın TTL'i kadar.
- **Negatif cache:** "böyle bir isim yok (NXDOMAIN)" da saklanır; süresini SOA kaydındaki `minimum` belirler (RFC 2308).

**Adım D — Hiçbiri değilse:** Resolver cevabı gidip bulmalı. İki yol var.

### 2.2 Yol 1: Forwarder'a iletme

Çoğu kurumsal/ev ortamında resolver internette tek tek dolaşmaz; sorguyu başka bir recursive resolver'a (**forwarder**) devreder. Örnek: DC `example.com`'u bilmiyor → `8.8.8.8`'e recursive soruyor → `8.8.8.8` tüm işi yapıp cevabı getiriyor → DC cache'leyip istemciye veriyor.

Neden: merkezi cache verimi, filtreleme/kontrol, basitlik (iç sunucunun root hints/internet erişimine ihtiyacı kalmaz).

**Conditional forwarder (şartlı yönlendirme):** "Şu domain için şu sunucuya git, gerisi için normal forwarder'a." İki AD ormanının (forest) birbirini görmesi için klasik yöntem:
```
*.partner.local  →  10.50.0.10 (partnerin DNS'i)
diğer her şey     →  8.8.8.8
```

### 2.3 Yol 2: Resolver kendisi çözüyor (root hints)

Forwarder tanımlı değilse resolver işi kendisi yapar. Başlangıç noktası, 13 root sunucunun isim+IP'sini içeren, yazılıma gömülü **root hints** dosyasıdır (`named.root`). Bundan sonrası Aşama 3'tür. Yani forwarder kullanan resolver Aşama 3'ü hiç yapmaz (forwarder yapar); kullanmayan bizzat yürütür.

### 2.4 Recursive vs iteratif — pakete yansıması

Tek bir kullanıcı sorgusu perde arkasında şöyle görünür:

```
İstemci  --recursive-->  Resolver
                         Resolver  --iteratif-->  Root           (referral: .com'a git)
                         Resolver  --iteratif-->  TLD (.com)      (referral: example.com NS'lerine git)
                         Resolver  --iteratif-->  Authoritative   (cevap: IP)
İstemci  <--cevap------  Resolver
```

`dig example.com` normal recursive sorgudur. `dig +trace example.com`, dig'e "resolver'ın yerine geç, iteratif adımları bana göster" dedirtir.

### 2.5 Güvenlik: açık resolver ve cache poisoning'in temeli

Adım A'daki `REFUSED` kontrolünün var olma sebebi buraya bağlanır. Bir recursive resolver herkese açık bırakılırsa (**open resolver**) iki tehlike doğar:

- **DNS Amplification DDoS:** Saldırgan kaynak IP'yi kurban gibi gösterir (spoof), küçük bir sorgu (örn. `ANY`) gönderir, resolver çok büyük cevabı kurbana yollar. 60 byte gönderip kurbana ~4000 byte yollatmak ~70x büyütme demektir. `REFUSED` kontrolü tam bunu engeller.
- **Cache poisoning hedefi olmak:** Resolver iteratif çözüm sırasında authoritative'den UDP ile cevap bekler. Saldırganın amacı gerçek cevaptan **önce** sahte bir cevabı ulaştırmaktır. Kabul için aynı anda tutturması gerekenler: (1) 16-bit Transaction ID, (2) rastgele kaynak port, (3) soru bölümü birebir, (4) gerçek cevaptan önce varmak. 2008 öncesi port sabit ve ID tahmin edilebilirdi; **Kaminsky saldırısı** bunu sistematik hale getirdi. Çözüm **source port randomization** (RFC 5452) — Aşama 1.7'deki rastgele kaynak portun tek sebebi budur. Kalıcı çözüm **DNSSEC** (cevapları kriptografik imzalayıp sahtesini matematiksel reddetmek).

---

## AŞAMA 3: İteratif Yolculuk (Root → TLD → Authoritative)

Resolver forwarder kullanmıyorsa ismi kendisi çözer. Soru her adımda **aynıdır**: "`example.example.com`'un A kaydı nedir?" Değişen, sorulan sunucu ve alınan cevabın türüdür.

### 3.1 İsim ağacı ve delegasyon

DNS ters bir ağaçtır; her isim sağında gizli bir noktayla biter:

```
                    . (root)
                 /     |     \
              com     org     net ...
             /   \
      example   google
        |
   example.example   (subdomain)
```

`example.example.com.` **sağdan sola** okunur çünkü yetki böyle akar. Kimse her şeyi bilmez; herkes sadece **bir alt katmandan kimin sorumlu olduğunu** bilir. Bu **delegasyon**, DNS'in ölçeklenebilmesinin sebebidir.

### 3.2 Adım adım

**Adım 0 — Root adresi nereden?** Resolver'ın içindeki gömülü **root hints** dosyası (13 root sunucu: `a.root-servers.net` … `m.root-servers.net`). 13 **isim** vardır ama 13 makine değil: **anycast** ile aynı IP dünyada 1500'den fazla fiziksel kopyada yayınlanır.

**Adım 1 — Root'a sor:**
```
Resolver → Root:  "example.example.com A?"
Root → Resolver:  "Bilmiyorum. .com için şu NS'lere git: a.gtld-servers.net, ... (ve IP'leri)"
```
Bu cevaba **referral** denir. Root IP'yi değil, bir sonraki adımı verir. ANSWER boş; AUTHORITY'de `.com` NS kayıtları; ADDITIONAL'da onların IP'leri (**glue record**). `AA` biti yoktur (root, `.com`'un sahibi değil).

**Adım 2 — TLD (.com) sunucusuna sor:**
```
Resolver → .com TLD:  "example.example.com A?"
TLD → Resolver:       "Bilmiyorum. example.com için yetkili NS'ler: ns1.example.com, ... (ve IP'leri)"
```
Yine referral. TLD sunucusu milyonlarca domainin IP'sini tutmaz; sadece her domain için "yetkili sunucusu kim" bilgisini tutar. Bu bilgi, domain sahibinin registrar'da girdiği NS kayıtlarından gelir.

**Adım 3 — Authoritative sunucuya sor:**
```
Resolver → example.com authoritative:  "example.example.com A?"
Authoritative → Resolver:              "example.example.com = 93.184.x.x"  (AA biti = 1)
```
Zincirin sonu. Bu sunucu zone'un sahibidir; cevap **authoritative**'dir, ANSWER doludur.

**Adım 4 — Cache ve dönüş.** Resolver süreçte öğrendiği **her şeyi** (son A kaydı + `.com` NS'leri + `example.com` NS'leri) kendi TTL'leri kadar cache'ler. Bir sonraki sorguda root/TLD adımları atlanır.

### 3.3 Glue record (tavuk-yumurta problemi)

"example.com için `ns1.example.com`'a sor" denince sorun çıkar: `ns1.example.com`'un IP'sini bulmak için `example.com`'u çözmen gerekir, ama onu çözmek için bu sunucuya ulaşman lazım — sonsuz döngü. Çözüm: NS kaydı domainin **kendi içinde** bir sunucuya işaret ediyorsa, TLD o sunucunun IP'sini de ADDITIONAL bölümünde verir. Bu ekstra IP kaydı **glue record**'dur. NS başka bir domaindeyse (`ns1.cloudflare.com`) glue gerekmez.

### 3.4 QNAME minimization (RFC 9156)

Klasik DNS'te resolver root'a ve TLD'ye bile tam ismi sorar — gereksiz bilgi sızıntısı (root senin tam adresini görür). Modern resolver'lar gizlilik için her sunucuya sadece o katmanın bilmesi gerekeni sorar:
- Root'a: `com NS?`
- TLD'ye: `example.com NS?`
- Authoritative'e: tam isim `example.example.com A?`

Cloudflare, Google, Unbound'da varsayılan açıktır.

### 3.5 `dig +trace` okuma yöntemi

Çıktı bloklar halinde gelir; her bloğun **en altındaki** `Received ... from X` satırı "bu bilgiyi X verdi" der:

```
.      518400  IN  NS  a.root-servers.net.        ← root hints
;; Received ... from 192.168.1.1#53

com.   172800  IN  NS  a.gtld-servers.net.        ← root referral (.com'a)
;; Received ... from 198.41.0.4#53(a.root-servers.net)

example.com.  172800  IN  NS  a.iana-servers.net. ← TLD referral (example.com'a)
;; Received ... from 192.5.6.30#53(a.gtld-servers.net)

example.com.  86400  IN  A  93.184.x.x            ← authoritative cevap
;; Received ... from 199.43.x.x#53(a.iana-servers.net)
```

Yukarıdan aşağı: root → gtld (TLD) → iana (authoritative). Bütün Aşama 3 bu dört `Received from` satırında özetlenir.

### 3.6 Güvenlik köşesi

- **Domain hijacking:** Saldırgan registrar hesabını ele geçirip NS kayıtlarını değiştirirse, zincir baştan sahte authoritative'e yönlenir — zehirlemeye bile gerek kalmaz.
- **Lame delegation:** TLD'nin işaret ettiği NS yetkili değilse/cevap vermiyorsa çözüm `SERVFAIL` olur. Subdomain takeover'ların bir kısmı buradan doğar (NS hâlâ artık senin olmayan bir bulut kaynağına işaret ediyorsa).
- **Zone transfer (AXFR):** Yanlış yapılandırılmış authoritative sunucu, tüm zone'u (bütün subdomainler) `dig axfr @ns example.com` ile dışarı verebilir — OSINT'in altın madeni.

---

## AŞAMA 4: Cevabın Dönüşü ve Cache'lenmesi

### 4.1 Geri dönüş zinciri

Cevap gidişin tersine akar ve **her durak kendi cache'ine kopya bırakır**:

```
Authoritative  →  Recursive resolver  →  OS (stub)  →  Tarayıcı
                       (cache'ler)        (cache'ler)   (cache'ler)
```

Aynı kayıt artık üç ayrı yerde durur ve her birinin **kendi geri sayımı** vardır. "DNS değişikliği neden hemen yansımadı?" sorusunun cevabı tek yer değil, bu üç katmanın en uzunudur.

### 4.2 TTL — kaydın raf ömrü

Her kaydın yanındaki **TTL (Time To Live)** saniye cinsindendir ve kaydın sahibi (authoritative zone) belirler. `dig` çıktısında ikinci sütundur:

```
example.com.   3600   IN   A   93.184.x.x
               ^^^^ TTL = 1 saat
```

Resolver cache'ten verirken TTL'i **kalan süreye düşürerek** gösterir:
```
İlk sorgu:   example.com.  3600  IN  A  93.184.x.x
5 sn sonra:  example.com.  3595  IN  A  93.184.x.x   ← cache'ten geldi
```
Yani TTL tam yuvarlaksa (3600) muhtemelen taze; kırıksa (3595) cache'ten.

**Denge:** Düşük TTL (60 sn) → hızlı yayılım, failover/load-balancing için iyi, ama çok sorgu. Yüksek TTL (86400) → az sorgu, hızlı yanıt, ama değişiklik 1 güne kadar bazı kullanıcılara ulaşmaz. **Pratik taktik:** Sunucu taşıması öncesi TTL günler önceden 60'a düşürülür, geçişten sonra tekrar yükseltilir.

### 4.3 Negatif cache ve SOA

NXDOMAIN cevabının ne kadar cache'leneceğini, domainin **SOA kaydındaki `minimum` alanı** belirler (A kaydının TTL'i değil):

```
dig SOA example.com

example.com.  3600  IN  SOA  ns.icann.org. noc.dns.icann.org. (
                2024010101   ; serial  (zone sürüm numarası)
                7200         ; refresh
                3600         ; retry
                1209600      ; expire
                3600 )       ; minimum → NEGATİF CACHE SÜRESİ
```

**Klasik tuzak:** Yeni bir kaydı oluşturmadan **hemen önce** onu sorgularsan, "yok" cevabı negatif cache'e yazılır; kayıt gerçekte var olsa bile süre dolana kadar "yok" almaya devam edersin.

### 4.4 Cevap paketinin yapısı ve RCODE

| Bölüm | İçerik |
|---|---|
| Header | Transaction ID, flag'ler, RCODE, sayaçlar |
| Question | Ne sorulmuştu (aynen yankılanır) |
| Answer | Asıl cevap (A, AAAA, CNAME...) |
| Authority | Kim sorumlu (NS; negatif cevapta SOA) |
| Additional | Glue record'lar, EDNS bilgisi |

RCODE'lar (Aşama 2.1'de de geçti): `NOERROR` (başarılı; Answer boş olabilir = isim var ama o tipte kayıt yok), `NXDOMAIN` (isim yok), `SERVFAIL` (çözülemedi), `REFUSED` (reddedildi).

### 4.5 Flag'ler

`;; flags: qr aa rd ra;`

- `qr` → bu bir cevap
- `aa` → authoritative (zone sahibinden). Normal bir public resolver'dan `example.com` sorunca `aa` **görmezsin**.
- `rd` → recursion desired (istemci istedi)
- `ra` → recursion available (sunucu bu hizmeti veriyor)
- `ad` → authenticated data (DNSSEC doğrulaması başarılı)

`aa` yok + `ra` var → "cevap bir resolver'ın cache/recursion'ından geldi, zone sahibinden değil".

### 4.6 UDP, TCP ve EDNS

DNS klasik olarak **UDP/53** kullanır (hızlı, tek git-gel). UDP'nin tarihsel sınırı 512 byte'tı. Cevap büyükse:
- **Eski yöntem:** Sunucu **TC (Truncated) bitini** 1 yapar; resolver aynı sorguyu **TCP/53** ile tekrar sorar.
- **Modern yöntem — EDNS0 (RFC 6891):** Sorguya OPT kaydı eklenip "4096 byte'a kadar UDP alabilirim" denir:
```
;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
```
DNSSEC imzaları ve çok kayıtlı cevaplar 512'yi rahat aşar; EDNS olmadan modern DNS çalışmaz. TCP/53'ü firewall'da tümüyle kapatmak klasik hatadır (büyük cevaplar ve AXFR sessizce patlar).

### 4.7 Bağlantı kurulduktan sonra

Tarayıcı IP'yi aldığı an DNS'in işi biter; gerisi TCP handshake, TLS, HTTP'dir. Bu yüzden bağlantı kurulduktan sonra DNS çökse bile **mevcut bağlantı** çalışmaya devam eder (keep-alive, HTTP/2, websocket); DNS yalnızca **yeni** bir isim çözülürken gerekir. Aynı mantıkla, bir domainin kaydını değiştirmek (veya zehirlemek) mevcut bağlantıları etkilemez, sadece yeni bağlantıları ve TTL dolduktan sonraki sorguları.

Ek: büyük siteler birden çok A kaydı döner (**DNS round-robin**, basit yük dağıtımı); istemci ilkini dener, olmazsa diğerine geçer.

---

## AŞAMA 5: DNS Başarısız Olunca — LLMNR, NBT-NS, mDNS

İki yaygın yanılgıyı baştan düzeltmek gerekir: (1) NetBIOS "dışarıdaki" bir ismi (internet domaini) **çözmez**; bu mekanizmalar **sadece yerel ağda (LAN)** broadcast/multicast ile çalışır. (2) Bu fallback'ler zincirin **en sonunda**, DNS başarısız olunca ve pratikte neredeyse her zaman **tek kelimelik, soneki olmayan isimlerde** (`\\fileserver`) devreye girer.

### 5.1 Ne zaman devreye girer?

Windows'ta kullanıcı `\\muhasebe-pc` yazdı:
1. Tek kelime → DNS suffix eklenir: `muhasebe-pc.corp.local`, DNS'e sorulur.
2. DNS "yok" (NXDOMAIN) der.
3. Windows pes etmez, yerel ağa dönüp "bu isim kimin?" diye bağırır: **LLMNR** → **NBT-NS** → **mDNS**.

Kritik: bu üçü de **merkezi ve kimliği doğrulanmış bir otoriteye** sormaz; yerel ağdaki *herkese* sorar ve **ilk cevap vereni** doğru kabul eder. Güvenlik açığının tamamı bu cümlededir.

### 5.2 Üç mekanizma

- **LLMNR** (Link-Local Multicast Name Resolution): UDP **5355**, multicast (224.0.0.252 / ff02::1:3). DNS'in küçük kardeşi.
- **NBT-NS** (NetBIOS Name Service): UDP **137**, broadcast. Çok eski (DOS/LAN Manager mirası), isimler 15 karakter + büyük harf. WINS tanımlıysa önce ona sorar.
- **mDNS** (Multicast DNS): UDP **5353**, multicast (224.0.0.251). Apple Bonjour'un temeli; `.local` isimleri, yazıcı/IoT keşfi.

Ortak günah: **kimlik doğrulaması yok, merkezi otorite yok, ilk cevap kazanır.**

### 5.3 Saldırı: LLMNR/NBT-NS Poisoning (Responder)

1. Kullanıcı yanlış bir isim yazar (veya bir login script eski bir sunucuya bağlanmaya çalışır) → DNS'te yok → kurban LLMNR/NBT-NS ile **tüm LAN'a** "bu isim kimde?" diye sorar.
2. Meşru kimse cevap vermez.
3. Ağdaki saldırgan (**Responder** çalıştırıyor) bu multicast/broadcast'i duyar ve **"evet, o benim!"** diye sahte cevap yollar.
4. Kurban saldırganı gerçek sunucu sanıp bağlanmaya çalışır; SMB'de Windows **otomatik olarak** kullanıcının kimlik bilgisini (NTLM) sunar.
5. Saldırgan **NTLMv2 challenge-response hash**'ini yakalar.

Yakalanan hash ile: **offline cracking** (`hashcat -m 5600`, zayıf parolalar saniyeler içinde) veya **NTLM relay** (hash'i kırmadan canlı olarak başka makineye yansıtmak — SMB signing kapalıysa, `ntlmrelayx`).

```bash
# Örnek (yalnızca kendi izole lab ortamında):
sudo responder -I eth0
# Kurban var olmayan bir isme erişmeye çalıştığında hash düşer:
# [SMB] NTLMv2-SSP Hash : kullanici::DOMAIN:...
hashcat -m 5600 yakalanan_hash.txt rockyou.txt
```

> **Etik/kapsam:** Bu teknikler yalnızca sahip olunan izole bir lab ortamında veya yazılı izinli bir sızma testinde çalıştırılır. Rastgele bir ağda (işyeri/okul/kafe Wi-Fi'si) Responder çalıştırmak başkalarının kimlik bilgilerini toplamaktır ve suçtur.

### 5.4 Tespit (SOC tarafı)

- **Tripwire mantığı:** Ağda asla var olmayan bir isme kimse meşru bağlanmaz; `\\sahtesunucu123` için LLMNR cevabı alan varsa, cevap vereni bul.
- **SIEM:** Olağandışı UDP 5355 (LLMNR) ve 137 (NBT-NS) cevap trafiği, özellikle aynı kaynaktan çok sayıda isme "evet benim" demesi.
- **Aktif tespit:** Savunmacı kasıtlı sahte bir LLMNR sorgusu atıp cevap geleni yakalar (bal küpü sorgusu).
- **Wireshark filtresi:** `llmnr || nbns || mdns`

### 5.5 Savunma

- **LLMNR kapatma:** GPO → Computer Configuration → Administrative Templates → Network → DNS Client → *Turn off multicast name resolution* → Enabled.
- **NBT-NS kapatma:** Her adaptörde "NetBIOS over TCP/IP"i devre dışı bırak (GPO/DHCP ile merkezi).
- **mDNS:** Gerekmiyorsa kapat / segmentle.
- **Derinlemesine savunma:** SMB signing'i zorunlu kıl → NTLM relay büyük ölçüde etkisizleşir (relay edilen oturum imzalanamaz).

---

## Tüm Yolculuk Tek Resimde

```
Kullanıcı "example.example.com" yazar
│
├─ AŞAMA 1: Kendi makine (stub resolver)
│   tarayıcı cache → OS cache → /etc/hosts → [suffix ekleme]
│   bulunamazsa ↓ (resolv.conf'taki sunucuya recursive sorgu, RD=1)
│
├─ AŞAMA 2: Recursive resolver (DC / modem / 8.8.8.8)
│   erişim? → authoritative zone? → cache? → forwarder (Yol 1) / kendi çözer (Yol 2)
│
├─ AŞAMA 3: İteratif yolculuk (yalnızca Yol 2'de)
│   Root (referral→.com) → TLD .com (referral→example.com NS) → Authoritative (IP, AA=1)
│
├─ AŞAMA 4: Cevap döner, 3 katmana cache'lenir
│   TTL geri sayımı, negatif cache (SOA minimum), RCODE, flag'ler, EDNS/TCP fallback
│
└─ AŞAMA 5: DNS BAŞARISIZSA (yalnızca LAN, genelde tek kelimelik isim)
    LLMNR (5355) → NBT-NS (137) → mDNS (5353)
    → kimlik doğrulaması yok → Responder sahte cevap → NTLMv2 hash → crack/relay
```

## Pratik Araç Kutusu

```bash
dig example.com                 # normal recursive sorgu (flag'leri, TTL'i oku)
dig +trace example.com          # root → TLD → authoritative zincirini adım adım gör
dig +short example.com          # sadece IP (script'ler için)
dig NS com.                     # .com TLD sunucuları
dig NS example.com              # domainin authoritative NS'leri
dig SOA example.com             # negatif cache süresi (minimum alanı)
dig @8.8.8.8 example.com        # belirli bir resolver'a sor
dig axfr @ns example.com        # zone transfer denemesi (yanlış yapılandırma testi)
getent hosts example.com        # OS zincirini kullan (hosts dahil) — dig'in aksine
```

Wireshark ana filtre: `dns || llmnr || nbns || mdns`

---

**Up:** [Home](Home.md)
**Related:** [Active Directory](Active%20Directory.md) · [Windows Persistence - Index](Windows%20persistence/Windows%20Persistence%20-%20Index.md) · [THM-Ra-Writeup](THM-WriteUps/THM-Ra-Writeup.md)
