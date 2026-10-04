---
title: "Linux Privilege Escalation — Temel Adımlar"
date: 2026-10-02
tags: [linux, privesc, cheatsheet]
---
# Linux Privilege Escalation — Temel Adımlar

```
find / -perm -4000 2>/dev/null    # SUID
find / -perm -2000 2>/dev/null    # SGID
```

**3. baksteen veya users grubunun yazma izni olduğu dosya/dizinleri bulma:**

```
find / -writable -group baksteen 2>/dev/null
find / -writable 2>/dev/null -type f
```

**4. sudo yetkisi var mı kontrol et:**

```
sudo -l
```

**5. cron job'ları incele (genelde özel gruplara ait script'ler burada olur):**

```
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ 2>/dev/null
```

**6. /etc/passwd ve /etc/group dosyalarını incele:**

```
cat /etc/passwd
cat /etc/group
```

---

**Up:** [Home](Home.md)
**Related:** [File Inclusion - Path Traversal](WEB/File%20Inclusion%20-%20Path%20Traversal.md) · [Active Directory](Active%20Directory.md)
