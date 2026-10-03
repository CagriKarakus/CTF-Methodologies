
### Tampering with Unprivileged Accounts

Assign group membership ,

```
net localgroup administrator fakeuser /add
```

if this look too sus you can add it to "Backup Operators, Remote Management Users" groups also.
- The groups must be enabled.
- **LocalAccountTokenFilterPolicy** must be disabled. It weont allow you toget control over winrm. Sebebi **UAC (User Account Control)**. UAC'nin `LocalAccountTokenFilterPolicy` adlı bir özelliği var. Bu özellik, bir **yerel hesap** uzaktan (remote) giriş yaptığında o hesabın yönetici ayrıcalıklarını token'dan söküp atıyor.

Önemli ayrım şu:

- Grafik arayüzden (local session) bağlanırsan UAC üzerinden yetkini yükseltebilirsin (elevate).
- Ama WinRM ile bağlanıyorsan, kısıtlı (limited) bir access token'a mahkumsun — yönetici ayrıcalığın hiç yok.

- birden fazla düşük profilli kullanıcı hesabına Administrator ile aynı parolayı verirsin; biri fark edilip kapatılsa bile diğerleri aynı yetkiyle elinde kalır, hepsi aynı hash'le pass-the-hash yapılabilir.


