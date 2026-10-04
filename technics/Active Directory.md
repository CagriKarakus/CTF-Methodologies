---
title: "Active Directory — Saldırı Checklist"
date: 2026-09-28
tags: [active-directory, methodology, checklist, windows]
---
# Active Directory — Saldırı Checklist

### Checklist:

Active Directory:
- [ ] Scan All the ports.
- [ ] Find usernames:
	- [ ] Check anonymous access over smb and rpc and attempt stuff like, rid-brute, --users with netexec and enumdouser with rpc to get list of users in domain without needed  in credentials
	- [ ] Check usernames with kerbrute
- [ ] Test as-rep roasting after you have collected theusernames.
- [ ] Check smb shares and ldap information with anonymous access
- [ ] Enumerate ldap and every other relevant protocol you can find useful information with.
- [ ] Check for kerberoasting after you have username and password.
- [ ] Try authenticationg with every possible protocol with those set of credentials. winrm, rdp, mssql, smb, rpc, ldap etc.
- [ ] Enumerate shares for eveery user you get access to, start with checking public share with anonymous access.
- [ ] Run bloodhound and check for basic attack like DCsync. Also checks for other paths bloodhound may find.
- [ ] If you get shell as a user, check for privesc, and dump all hashes an collect them in a file for possible bruteforcing and lateral movement
- [ ] If it's an AD network, check for additional network adaprters in case opf pivoting bein needed. If so, set up a pivot and relay all tools over that "jumpbox" so you can target the other machines in the other network.
- [ ] Remember to bruteforce different protocols with credentials you have. Remember to use NTLM authentication too
- [ ] Check UDP ports.
- [ ] Rescan if youre stuck, verify tools are working properly and you're running them properly

---

**Up:** [Home](Home.md)
**Related:** [THM-Ra-Writeup](THM-WriteUps/THM-Ra-Writeup.md) · [Windows Local Persistence](Windows%20persistence/Windows%20Local%20Persistence.md) · [linux Privesc basic adımları](linux%20Privesc%20basic%20ad%C4%B1mlar%C4%B1.md)
