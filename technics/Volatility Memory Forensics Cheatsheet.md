---
title: Volatility Memory Forensics Cheatsheet
date: 2026-10-18
tags: [forensics, memory-forensics, volatility, volatility2, volatility3, linux, ctf, cheatsheet, lime]
---

# Volatility Memory Forensics Cheatsheet

> Genel amaçlı hafıza (RAM) analizi rehberi: kurulum → hazırlık → profil/symbol → triage akışı → plugin listesi → dosya çıkarma → sorun giderme.
> Linux ağırlıklı (Volatility 2.6.1 + Volatility 3), Windows için kısa bölüm var.
> Bir CTF makinesine özel değil; yeni bir `.mem` / `.lime` / `.raw` dosyası gelince baştan sona uygulanacak şekilde yazıldı.

## 0. Hızlı karar ağacı (TL;DR)

1. Dosya ne? `file dump.mem` + `ls -lh` (boyut ≈ RAM boyutu).
2. İşletim sistemi ne?
   - `strings -a dump.mem | grep -m3 "Linux version"` → Linux (banner çıkar)
   - `vol -f dump.mem banners.Banners` (Vol3) → Linux banner
   - `vol.py -f dump.mem imageinfo` (Vol2) → Windows
3. Linux ise: **banner → distro + kernel sürümü** → eşleşen **profil (Vol2)** veya **ISF symbol (Vol3)** bul/üret.
4. `linux_banner` / `banners` ile profilin doğru olduğunu doğrula.
5. Triage: process → bash history → network → dosyalar → persistence (cron/systemd) → rootkit kontrolleri.
6. Şüpheli dosyayı çıkar → `file`, `strings`, `md5sum/sha256sum`.

---

## 1. Hangi araç ne zaman?

| Araç | Güçlü yanı | Not |
|---|---|---|
| **Volatility 2.6.1** | Çok eski/çok yeni Linux profil bazlı analiz, CTF writeup'larının çoğu bunun plugin isimleriyle (`linux_*`) | Python 2 ister. Profil = `module.dwarf` + `System.map` zip'i |
| **Volatility 3** | Aktif geliştirilen sürüm, Python 3, otomatik Windows symbol indirme | Linux için ISF (JSON) symbol dosyası gerekir. Plugin isimleri `linux.pslist.PsList` formatında |
| **MemProcFS** | Hafızayı sanal dosya sistemi olarak mount eder (Windows'ta çok iyi) | Linux desteği sınırlı; statik `linux.mem` için genelde uygun değil |
| `strings` + `grep` | Hızlı ilk bakış (flag, URL, parola, komut) | `strings -a` kullan; `-t d` offset verir |
| Bulk Extractor | E-posta, URL, anahtar, kredi kartı gibi artefaktları toplar | Ham image üstünde çalışır |
| `foremost` / `photorec` | File carving | Hafıza dosyasında parça parça sonuç verir |

**Kural:** CTF sayfası "Volatility 2.6.1 kullan" diyorsa 2.6.1 kullan. Vol3 Vol2 profillerini okumaz.
İkisini yan yana kurabilirsin.

---

## 2. Kurulum (Kali / Debian)

### 2.1 Volatility 2.6.1 (Python 2)

Referans makale: Sean Whalen — *How to install Volatility 2 and Volatility 3 on Debian, Ubuntu or Kali Linux* (seanthegeek.net/1172).

```bash
# Derleme araçları + bağımlılıklar
sudo apt install -y build-essential git libdistorm3-dev yara libraw1394-11 libcapstone-dev capstone-tool tzdata
sudo apt install -y libcrypt-dev            # <-- ÖNEMLİ: distorm3/pycrypto derlemesi için crypt.h

# Python 2 + pip
sudo apt install -y python2 python2.7-dev libpython2-dev
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
sudo python2 get-pip.py
sudo python2 -m pip install -U setuptools wheel

# Python 2 paketleri (user install)
python2 -m pip install -U distorm3 yara pycrypto pillow openpyxl ujson pytz ipython capstone
#   pycrypto derlenmezse:  python2 -m pip install pycryptodome

# yara için (makale adımı)
sudo python2 -m pip install yara
sudo ln -s /usr/local/lib/python2.7/dist-packages/usr/lib/libyara.so /usr/lib/libyara.so

# Volatility 2'nin kendisi
python2 -m pip install -U git+https://github.com/volatilityfoundation/volatility.git
```

**Bilinen hata:** `fatal error: crypt.h: No such file or directory` → `sudo apt install libcrypt-dev` yap, sonra distorm3/pycrypto'yu tekrar kur.
Pip ilk hatada durduğu için aynı komuttaki diğer paketler (pillow, openpyxl...) de kurulmamış olabilir; komutu tekrar çalıştır.

**PATH (user install ise):** `vol.py` "command not found" derse
```bash
echo 'export PATH=$HOME/.local/bin:$PATH' >> ~/.zshrc   # bash için ~/.bashrc
. ~/.zshrc
which vol.py
```
(Kali'de `~/.profile` genelde `~/.local/bin`'i zaten ekler; çalışıyorsa dokunma.)

**Kurulum testi**
```bash
vol.py --info | head -30                    # sürüm + Windows profilleri (Linux profili YOKTUR, normal)
vol.py --info | grep -i "^linux_" | head    # linux_* pluginleri geldi mi
python2 -c "import distorm3; print('distorm3 ok')"
python2 -c "import Crypto;  print('crypto ok')"
```

### 2.2 Volatility 3

```bash
sudo apt install -y volatility3            # Kali'de hazır paket (komut: vol / vol3 / volatility3)
# veya izole kurulum:
python3 -m venv ~/venv-vol3 && . ~/venv-vol3/bin/activate
pip install volatility3
```
```bash
vol -h | grep -i linux                     # bu sürümde hangi linux pluginleri var
vol -f dump.mem banners.Banners            # kernel banner'ı
```

---

## 3. Çalışma ortamı hazırlığı (her makinede)

```bash
mkdir -p ~/forensics/<vaka>/{profile-build,out}
cd ~/forensics/<vaka>
sha256sum dump.mem > dump.mem.sha256        # delil bütünlüğü
```

Vol2 için kısayol değişkenleri (her seferinde uzun parametre yazmamak için):
```bash
export VOLATILITY_PLUGINS=$HOME/forensics/<vaka>/profile-build
export VOLATILITY_LOCATION=file://$HOME/forensics/<vaka>/dump.mem
export VOLATILITY_PROFILE=<ProfilAdi>
vol.py linux_pslist                          # artık -f / --profile gerekmez
```
- `--plugins=...` içinde `~` kullanma (shell açmaz), `$HOME` kullan.
- Komut satırındaki `-f` / `--profile`, env değişkenini ezer.

Çıktıları kaydet (rapor/not için):
```bash
vol.py linux_pslist | tee out/pslist.txt
vol.py linux_bash   | tee out/bash.txt
```

---

## 4. Linux: Profil / Symbol edinme

### 4.1 Önce banner'ı al

```bash
strings -a dump.mem | grep -m3 "Linux version"
# Vol3:  vol -f dump.mem banners.Banners
```
Örnek banner'dan okunacaklar: **distro** (Ubuntu/Debian/CentOS), **kernel tam sürümü** (örn. `5.4.0-166-generic`), **mimari** (x64). Profil bunlarla *birebir* eşleşmeli.

### 4.2 Hazır profil var mı?
- CTF sayfasını ve indirilen dosyaları kontrol et (zip içinde `module.dwarf` + `System.map`).
- Varsa `profile-build/` klasörüne koy ya da `.../volatility/plugins/overlays/linux/` içine kopyala.
- Volatility symbol deposu (`volatilityfoundation/volatility` wiki → profiles) bazı yaygın kernel'ler için hazır zip içerir.

### 4.3 Vol2 profili üret (Docker ile, distro'yla aynı ortamda)

```bash
sudo apt install -y docker.io && sudo systemctl enable --now docker
sudo docker run -it --rm -v ~/forensics/<vaka>/profile-build:/out ubuntu:20.04 bash   # distro/sürümü banner'a göre seç
```
Container içinde (Ubuntu örneği — kernel sürümünü banner'dan al):
```bash
apt update
apt install -y build-essential git dwarfdump zip wget
apt install -y linux-headers-<KVER> linux-image-unsigned-<KVER>    # <KVER> örn: 5.4.0-166-generic
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility/tools/linux
make KVER=<KVER>
ls -l module.dwarf                                                  # birkaç MB olmalı
zip /out/Ubuntu_<KVER>.zip module.dwarf /boot/System.map-<KVER>
exit
```
Notlar:
- `MODULE_LICENSE` uyarısı zararsız.
- `/lib/modules/<KVER>/build: No such file` hatası = headers paketi kurulmamış.
- Eski kernel apt'de bulunamazsa: Launchpad build sayfasından `.deb` indir (`linux-headers-*`, `linux-headers-*-generic`, `linux-modules-*`, `linux-image-unsigned-*`) ve `apt install ./*.deb`.
- Debian için eski paketler: `snapshot.debian.org`; CentOS/RHEL için: `vault.centos.org` (kernel-devel + kernel-debuginfo).
- Container'ı çalışan kernel'le değil, **paketlerle** kuruyorsun; makinede o kernel'i boot etmen gerekmez.

Profili test et:
```bash
vol.py --plugins=$HOME/forensics/<vaka>/profile-build --info | grep -i <distro>
vol.py --plugins=... -f dump.mem --profile=<ProfilAdi> linux_banner
```
`linux_banner` çıktısı `strings` ile bulduğun banner'la aynıysa profil doğrudur.

### 4.4 Vol3 için symbol (ISF)

1. Önce hazır ISF ara (topluluk symbol depoları, Volatility symbol paketi `linux.zip`); `volatility3/symbols/linux/` altına koy.
2. Yoksa `dwarf2json` ile üret:
   - Gerekli: debug bilgili `vmlinux` (Ubuntu: `-dbgsym` / ddebs paketi, Debian: `linux-image-*-dbg`) veya `System.map` + kernel DWARF.
   - `dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-<KVER> > <KVER>.json` → `xz` ile sıkıştırıp symbols/linux/ içine koy.
3. Test: `vol -f dump.mem banners.Banners` sonra `vol -f dump.mem linux.pslist.PsList`.

---

## 5. Triage akışı (Linux, Vol2 isimleri)

Her adımda şüpheli şeyleri not al (PID, dosya yolu, IP, kullanıcı, zaman).

| # | Amaç | Komut |
|---|---|---|
| 1 | Doğrulama | `linux_banner`, `linux_dmesg`, `linux_cpuinfo` |
| 2 | Process listesi | `linux_pslist`, `linux_pstree`, `linux_psaux` (komut satırı argümanlarıyla) |
| 3 | Gizli process | `linux_psxview`, `linux_pidhashtable` |
| 4 | Shell geçmişi | `linux_bash` (+ `linux_bash_env`, `linux_bash_hash`) |
| 5 | Ağ | `linux_netstat`, `linux_ifconfig`, `linux_arp`, `linux_route_cache`, `linux_netscan` |
| 6 | Açık dosyalar | `linux_lsof [-p PID]` |
| 7 | Dosya sistemi | `linux_enumerate_files`, `linux_find_file`, `linux_mount`, `linux_recover_filesystem` |
| 8 | Persistence | cron, systemd, `.bashrc`, `rc.local`, `authorized_keys`, `ld.so.preload` (bkz. §8) |
| 9 | Rootkit/hook | `linux_check_syscall`, `linux_check_modules`, `linux_lsmod`, `linux_hidden_modules`, `linux_check_idt`, `linux_check_afinfo`, `linux_check_creds`, `linux_check_fop`, `linux_check_tty` |
| 10 | Kod enjeksiyonu | `linux_malfind`, `linux_proc_maps`, `linux_elfs`, `linux_library_list`, `linux_ldrmodules` |
| 11 | Tarama | `linux_yarascan -Y "string"` / `-y rules.yar` |
| 12 | Kernel ayarı | `linux_aslr_shift` (profil sorunlarında) |

### Sık kullanılan örnekler
```bash
vol.py linux_pslist | grep -vE "kworker|ksoftirqd|migration|rcu_|\[.*\]"   # kernel thread'leri ele
vol.py linux_psaux | grep -iE "nc |ncat|python|perl|bash -i|/tmp|/dev/shm|base64"
vol.py linux_bash
vol.py linux_netstat | grep -v UNIX
vol.py linux_lsof -p <PID>
vol.py linux_enumerate_files | grep -iE "cron|\.ssh|/tmp/|/dev/shm|\.bashrc|rc\.local"
vol.py linux_proc_maps -p <PID>
```

### `linux_bash` ipuçları
- Komutlar **bash process belleğinden** kurtarılır; `cat /dev/null > .bash_history` ile disk geçmişi silinmiş olsa bile bellekte kalabilir.
- Aynı komut tekrar tekrar ve aynı zaman damgasıyla görünebilir (bellekte yığılma); anlamlı olan **sıra** ve **içerik**.
- Çıktıda `???` / bozuk satırlar normaldir (kısmi bellek).
- Bundan çıkarılacaklar: indirilen dosyalar (`wget`, `curl`), derlenen binary'ler (`gcc x -o y`), `su`/`sudo` kullanımı, parola değişiklikleri, silinen dosyalar, persistence komutları, hafızayı alan komut (örn. LiME `insmod`).

---

## 6. Dosya çıkarma (extract)

### 6.1 Dosyayı bul
```bash
vol.py linux_enumerate_files | grep -i "<anahtar kelime>"
```
Çıktı sütunları: **inode adresi** (`0xffff...`) | **inode numarası** (ondalık) | **yol**

- Soru "inode numarası" istiyorsa → ondalık sütun (örn. `131127`), `0xffff...` adresi **değil**.
- İnode adresi `0x0`, numara `---` olan satırlar silinmiş dosyaların artık dizin kayıtlarıdır; içerik genelde çıkmaz.
- `.gch` uzantısı = GCC precompiled header, zararlı binary değil.

### 6.2 İçeriği çıkar
```bash
vol.py linux_find_file -i 0xffff... -O out/dosya.bin      # inode adresiyle
vol.py linux_find_file -F /tam/yol/dosya -O out/dosya.bin # yolla
file out/dosya.bin
md5sum out/dosya.bin ; sha256sum out/dosya.bin
strings -a out/dosya.bin | less
```
- Çıkarma **page cache**'ten yapılır; sayfalar bellekte değilse dosya eksik/sıfırlı çıkar. `file` çıktısı "data" ise veya boyut çok küçükse şüphelen.
- Çalışan process'in binary'si için: `linux_procdump -p <PID> -D out/` (bellekteki hali; disk dosyasıyla hash'i farklı olabilir).
- Process bellek bölgesi: `linux_proc_maps -p PID` → `linux_dump_map -p PID -s <başlangıç_adresi> -D out/`
- Tüm tmpfs/dosya ağacı: `linux_recover_filesystem -D out/fs/`
- Hash sorusunda **hangi dosya** istendiğine dikkat et (ör. gerçek `/usr/bin/pkexec` ile sahte `pkexecc` farklı şeylerdir).
- **Şüpheli binary'yi çalıştırma.** Analiz için `strings`, `objdump -d`, `readelf`, `ghidra` / `radare2` kullan; sanal makinede, ağ kapalıyken.

### 6.3 Binary'den IP/port çıkarma
```bash
strings -a out/bin | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}"
objdump -d out/bin | grep -B5 -A30 "<main>"
```
Port genelde string değil **tamsayıdır** ve ağ bayt sırasında (big-endian) saklanır: `htons(0x115c)` → `0x5c11` gibi görünür → 0x115c = 4444. `connect()` çağrısından önceki `mov` değerlerine bak.

---

## 7. Network analizi ipuçları

- `linux_netstat` çıktısında **ESTABLISHED** bağlantılar ve **LISTEN** portlar önemli. UNIX soketlerini `grep -v UNIX` ile ele.
- Ters kabuk (reverse shell): şüpheli process → dış IP:port'a ESTABLISHED. Saldırgan IP:portu = **uzak (remote)** adres sütunu.
- SSH ile giriş: yerel port 22, uzak taraf yüksek (ephemeral) port; saldırgan IP'si uzak adrestir.
- Bash geçmişindeki `wget <IP>/dosya` = dosyanın indirildiği sunucu (HTTP, port 80 varsayılan) → genelde saldırgan altyapısı.
- Cron/script içinde `/dev/tcp/<IP>/<PORT>` veya `nc <IP> <PORT>` kalıbını ara.

---

## 8. Persistence avı (Linux)

Bellekteki dosya listesinde şunlara bak:

```bash
vol.py linux_enumerate_files | grep -E "/var/spool/cron|/etc/cron|/etc/crontab|/etc/systemd|/etc/rc\.local|authorized_keys|\.bashrc|\.profile|ld\.so\.preload|/etc/profile\.d|/etc/init\.d"
```

| Yer | Ne ararsın |
|---|---|
| `/var/spool/cron/crontabs/<user>` | Kullanıcı crontab'ı (en sık CTF cevabı) |
| `/etc/cron.d/`, `/etc/crontab`, `/etc/cron.{hourly,daily,weekly,monthly}/` | Sistem cron'ları; varsayılanlar (`apt-compat`, `logrotate`, `dpkg`...) dışında kalan dosya |
| `/etc/systemd/system/*.service`, `~/.config/systemd/user/` | Yeni/şüpheli servis |
| `~/.bashrc`, `/root/.bashrc`, `/etc/profile.d/*` | Giriş sırasında çalışan komut |
| `~/.ssh/authorized_keys` | Eklenmiş anahtar |
| `/etc/rc.local`, `/etc/init.d/` | Boot'ta çalışan script |
| `/etc/ld.so.preload` | Kütüphane enjeksiyonu / rootkit |
| `/etc/passwd`, `/etc/shadow`, sudoers | Eklenen kullanıcı, değiştirilen parola |

Cron dosyası okuma:
```bash
vol.py linux_find_file -i 0xffff... -O out/cron.bin
cat out/cron.bin          # '#' ile başlayan satırlar yorum
```
Crontab satırı: `dk saat gün ay haftanın_günü  KOMUT` → ilk 5 alan zaman, geri kalanı **komut**.
Cevap formatı genelde `tam_yol:inode_numarası` (örn. `/var/spool/cron/crontabs/root:131127`).

---

## 9. Hafıza edinimi (acquisition) — referans

Kendi lab'ında hafıza almak gerekirse:

```bash
# LiME (kernel modülü)
git clone https://github.com/504ensicsLabs/LiME && cd LiME/src
make                                              # linux-headers-$(uname -r) kurulu olmalı
sudo insmod lime-$(uname -r).ko "path=/tmp/mem.lime format=lime"

# AVML (modül derlemeden, userland)
sudo ./avml /tmp/mem.lime
```
- Vol2 ve Vol3 `format=lime` dosyalarını doğrudan okur.
- Alındıktan sonra aynı makinenin **banner'ı + kernel paketleri** profil üretimi için gereklidir (`uname -r`, `/boot/System.map-*`).
- Bash geçmişinde `insmod lime-...ko` görmek = analiz edilen dump'ın bu şekilde alındığını gösterir (zararlı değil, edinim aracı).

---

## 10. Windows hızlı referans (Vol2 / Vol3)

| Amaç | Vol2 | Vol3 |
|---|---|---|
| Profil/OS bilgisi | `imageinfo`, `kdbgscan` | `windows.info` |
| Process listesi | `pslist`, `psscan`, `pstree`, `psxview` | `windows.pslist`, `windows.psscan`, `windows.pstree` |
| Komut satırı | `cmdline`, `cmdscan`, `consoles` | `windows.cmdline` |
| Network | `netscan` | `windows.netscan` |
| DLL / handle | `dlllist`, `handles`, `mutantscan` | `windows.dlllist`, `windows.handles` |
| Kod enjeksiyonu | `malfind`, `apihooks`, `ssdt` | `windows.malfind` |
| Dosya | `filescan`, `dumpfiles -Q <ofs> -D out/` | `windows.filescan`, `windows.dumpfiles --virtaddr/--physaddr` |
| Process dump | `procdump -p PID -D out/`, `memdump` | `windows.pslist --pid PID --dump` |
| Parola/hash | `hashdump`, `lsadump` | `windows.hashdump`, `windows.lsadump` |
| Registry | `hivelist`, `printkey -K "Software\..."` | `windows.registry.hivelist`, `windows.registry.printkey` |
| Servis | `svcscan` | `windows.svcscan` |
| Zaman çizelgesi | `timeliner`, `mftparser` | `timeliner.Timeliner` |

Vol2'de çalıştırma biçimi: `vol.py -f dump.raw --profile=Win7SP1x64 <plugin>`.
Vol3'te profil gerekmez: `vol -f dump.raw windows.pslist`.

---

## 11. Vol3 Linux plugin karşılıkları

| Vol2 | Vol3 |
|---|---|
| `linux_banner` | `banners.Banners` |
| `linux_pslist` | `linux.pslist.PsList` |
| `linux_pstree` | `linux.pstree.PsTree` |
| `linux_psaux` | `linux.psaux.PsAux` |
| `linux_bash` | `linux.bash.Bash` |
| `linux_netstat` | `linux.sockstat.Sockstat` |
| `linux_lsof` | `linux.lsof.Lsof` |
| `linux_lsmod` | `linux.lsmod.Lsmod` |
| `linux_check_syscall` | `linux.check_syscall.Check_syscall` |
| `linux_malfind` | `linux.malfind.Malfind` |
| `linux_proc_maps` | `linux.proc.Maps` |
| `linux_elfs` | `linux.elfs.Elfs` |
| `linux_mount` | `linux.mountinfo.MountInfo` |
| `linux_enumerate_files` / `linux_find_file` | `linux.pagecache.Files` / `linux.pagecache.InodePages` (yeni sürümler; `vol -h \| grep pagecache`) |

Vol3 örnek: `vol -f dump.mem linux.pslist.PsList`, çıktıyı dosyaya almak için `-r csv` / `-r json`.

---

## 12. Sorun giderme

| Belirti | Sebep / Çözüm |
|---|---|
| `vol.py: command not found` | `~/.local/bin` PATH'te değil (§2.1) |
| `crypt.h: No such file` (distorm3/pycrypto) | `sudo apt install libcrypt-dev`, paketleri tekrar kur |
| `No suitable address space mapping found` | Yanlış/uyumsuz profil, kernel sürümü tutmuyor, ya da dosya formatı farklı. Banner'ı tekrar doğrula, `linux_aslr_shift` dene |
| `--info` Linux profili göstermiyor | Profil zip'i `--plugins` klasöründe değil, ya da zip içinde `module.dwarf`/`System.map` adı yanlış |
| `--plugins=~/...` çalışmıyor | `~` genişlemez → `$HOME` kullan |
| `/lib/modules/<KVER>/build: No such file` (profil build) | Headers paketi eksik/yanlış sürüm |
| apt'de kernel paketi bulunamıyor | Launchpad `.deb` indir veya snapshot arşivi kullan |
| Çıkarılan dosya `data`/küçük/sıfır dolu | Page cache'te yok; başka kaynaktan (`procdump`, `linux_proc_maps`+`dump_map`, `strings` ile içerik) dene |
| Aynı komut çok uzun sürüyor | Normal (ilk çalıştırmada DTB/ASLR taraması); çıktıyı `tee` ile kaydet |
| Python 2 / pip uyarıları (EOL) | Zararsız |
| `sudo pip` ve user pip çakışması | Biri seçilmeli; user kopyası import yolunda önce gelir |

---

## 13. CTF soru tipi → komut eşlemesi

| Soru | Nereden bak |
|---|---|
| Kernel sürümü / OS | `linux_banner`, `strings` banner |
| Kötü amaçlı dosya / hash | `linux_bash` (indirilen/derlenen) → `linux_enumerate_files` → `linux_find_file` → `md5sum` |
| Saldırgan IP:Port | `linux_netstat`, cron/script içeriği, binary `strings`/`objdump`, bash `wget`/`nc` |
| Cron job yolu + inode | `linux_enumerate_files \| grep cron` (ondalık inode!) |
| Cron içindeki komut | `linux_find_file -i ... -O` → `cat` |
| Hangi kullanıcı / PID | `linux_pslist`, `linux_psaux`, `linux_bash` PID sütunu |
| Parola / kullanıcı değişikliği | `linux_bash` (`passwd`, `su`, `useradd`), `/etc/shadow` çıkar |
| Yetki yükseltme izi | `linux_bash` (`su`, `sudo`, exploit derleme), `linux_check_creds` |
| Hafıza nasıl alındı | `linux_bash` içinde `insmod lime...` |
| Rootkit var mı | `linux_check_syscall`, `linux_check_modules`, `linux_hidden_modules` |
| Silinen dosya içeriği | `linux_bash`, `linux_lsof`, `linux_find_file` (page cache'te kaldıysa), `linux_yarascan` |

---

## 14. Ek: Disk dışı / ham aramalar

```bash
strings -a -t d dump.mem | grep -iE "password|passwd|secret|flag\{|ssh-rsa|BEGIN (RSA|OPENSSH)" | head
strings -a -el dump.mem | grep -i "<kelime>"      # UTF-16LE (Windows)
bulk_extractor -o out/be dump.mem                 # URL, e-mail, ccn, domain
```

---

Up: [Home](Home.md)
Related: [Home](Home.md) · [SOC Investigations - Index](SOC-Investigations/SOC%20Investigations%20-%20Index.md)
