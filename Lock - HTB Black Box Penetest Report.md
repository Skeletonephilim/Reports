
**Date:** 22 May 2026  
**Target:** lock.htb (10.129.1.185)  
**Assessment Type:** Solo Black-Box (authorized HTB lab)  
**Platform:** Windows Server 2022 · Workgroup **LOCK**  
**Outcome:** Full host compromise — service account foothold, interactive user access, **SYSTEM**-level privilege escalation  

---

## Executive Summary

External black-box testing against Lock identified a **compounding chain of configuration and process failures** rather than a single patchable bug. An attacker with no prior credentials could recover a long-lived Gitea Personal Access Token (PAT) from public Git history, abuse an unreviewed push-to-production CI/CD path on IIS, obtain code execution as `ellen.freeman`, harvest recoverable RDP credentials from an mRemoteNG export, move laterally to `gale.dekarios`, and escalate to **NT AUTHORITY\SYSTEM** via an outdated PDF24 Creator MSI repair workflow (CVE-2023-49147).

**Finding count by severity:** 2 Critical · 4 High · 1 Medium  
**Primary business risk:** Unauthenticated external actor → website tampering, data theft, ransomware staging, and total loss of host integrity within a single engagement window.

---

## Scope & Methodology

**In scope:** TCP services on `10.129.1.185` — HTTP/IIS (80), SMB (445), Gitea (3000), RDP (3389). Web application and post-exploitation enumeration from acquired sessions.  
**Out of scope:** Social engineering, physical access, denial-of-service.  
**Method:** Evidence-ladder black box — full port scan before application assumptions; API enumeration before browser guessing; benign deploy proof before weaponized payload; post-shell `net user` and profile review before objective hunting.

**Representative toolchain:** `nmap`, `curl`, Gitea REST API, `git`, `msfvenom`/Metasploit handler, `meterpreter`, `gquere/mRemoteNG_password_decrypt`, `xfreerdp3`, `SetOpLock.exe`, `msiexec`.

---

## Findings

### Finding 1 — Gitea Personal Access Token Leak via Git History (Critical)

**CVSS v3.1:** 7.5 High — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**MITRE ATT&CK:** T1552.001 · T1213.003  
**OWASP 2025:** A07 Authentication Failures · A02 Security Misconfiguration  

**Vector:**  
The public Gitea API (`/api/v1/repos/search`) exposed `ellen.freeman/dev-scripts`. A prior commit to `repos.py` contained a hardcoded `PERSONAL_ACCESS_TOKEN` before the developer migrated to `os.getenv('GITEA_ACCESS_TOKEN')`. **Git history retains deleted secrets** unless explicitly purged — removing the line from `main` did not revoke the credential.

**Impact:**  
Full API access as `ellen.freeman`: enumerate and clone **private** repositories (including `website`), push commits, and impersonate the developer identity for downstream CI/CD abuse. Business impact includes source-code confidentiality loss and supply-chain trust collapse.

**Proof:**  
Unauthenticated search → commit diff showing hardcoded token removal → authenticated `GET /api/v1/user/repos` with recovered PAT returned `dev-scripts` and private `website`. *(Token value redacted: `[REDACTED_PAT]`.)*

**Recommendation:**  
- **Immediate:** Revoke all PATs; rotate dependent credentials.  
- **Short-term:** Run `gitleaks` / `trufflehog` across all repos; purge history or accept rotation if purge infeasible.  
- **Long-term:** Pre-commit hooks, CI secret scanning, short-lived scoped tokens only — never long-lived PATs in VCS.

**Defensive detection:** Gitea audit logs for PAT use from new IPs; shift-left secret scanning in CI; alert on `/api/v1/repos/search` followed by authenticated clone/push activity.

---

### Finding 2 — CI/CD Pipeline Abuse — Push-to-Production on IIS (Critical)

**CVSS v3.1:** 9.9 Critical — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`  
**MITRE ATT&CK:** T1195.002 · T1505.003  
**OWASP 2025:** A03 Software Supply Chain Failures  

**Vector:**  
The private `ellen.freeman/website` repository README documents automatic deployment to the production web server on every `git push`. Repository `index.html` matched live content on port 80; pushing `deploy_test.html` confirmed the pipeline. **No code review, signing, or staging gate** exists between developer push and IIS web root.

**Impact:**  
Arbitrary file upload to an executable context — specifically ASPX webshell deployment — yielding **remote code execution as `LOCK\ellen.freeman`** (IIS application pool identity). Enables persistence, internal reconnaissance, and credential harvesting on the server.

**Proof:**  
Benign HTML push served at `http://lock.htb/deploy_test.html` after `git push`. Subsequent push of `rev.aspx` (generated via `msfvenom -f aspx`) established a **Meterpreter** session when the resource was requested. Session username: `LOCK\ellen.freeman`.

**Recommendation:**  
- **Immediate:** Disable auto-deploy; audit and clean IIS web root.  
- **Short-term:** Build agents with manual approval; deploy to read-only paths; block `.aspx` upload via pipeline policy.  
- **Long-term:** Separate dev/staging/prod; WAF; file-integrity monitoring on `inetpub\wwwroot`.

**Defensive detection:** IIS logs for new `.aspx` files; correlation of Gitea push webhooks with web-root file creation; EDR alerts on `w3wp.exe` spawning `cmd.exe` / outbound reverse connections.

---

### Finding 3 — Exposed mRemoteNG Credential Storage (High)

**CVSS v3.1:** 7.8 High — `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`  
**MITRE ATT&CK:** T1552.001 · T1021.001  
**OWASP 2025:** A04 Cryptographic Failures  

**Vector:**  
Post-foothold enumeration of `C:\Users\ellen.freeman\Documents\config.xml` revealed an mRemoteNG connection export (`RDP/Gale`, user `Gale.Dekarios`) with AES-GCM–protected passwords. Protection is **keyed to the user profile and offline-recoverable** once exfiltrated — equivalent to stored interactive credentials on a service account workstation.

**Impact:**  
Lateral movement from compromised service account to interactive user `gale.dekarios` without password cracking. Access to user desktop, documents, and user-tier sensitive data. On this host, the user objective was under the Gale profile, not Ellen's.

**Proof:**  
`config.xml` exfiltrated via meterpreter → decrypted with `gquere/mRemoteNG_password_decrypt` → successful `xfreerdp3` authentication. *(Password redacted: `[REDACTED]`.)* RDP session established on port 3389.

**Recommendation:**  
- **Immediate:** Rotate Gale credentials; delete mRemoteNG exports from service profiles.  
- **Short-term:** Ban connection-manager exports on servers; use Credential Manager, PAM, or SSO.  
- **Long-term:** Tiered access model; LAPS; EDR credential-access rules on `.xml` under user Documents.

**Defensive detection:** Sysmon file-read on mRemoteNG paths; RDP logon (4624 Type 10) for Gale following anomalous `w3wp.exe`/meterpreter ancestry; DLP on outbound connection files.

---

### Finding 4 — Insecure PDF24 Creator MSI Installer — CVE-2023-49147 (Critical)

**CVSS v3.1:** 7.3 High — `CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H`  
**MITRE ATT&CK:** T1068 · T1574.010  
**OWASP 2025:** A06 Insecure Design  

**Vector:**  
PDF24 Creator **11.15.1** (`pdf24-creator-11.15.1-x64.msi` in `C:\_install`) is vulnerable to CVE-2023-49147. An oplock on `C:\Program Files\PDF24\faxPrnInst.log` during **`msiexec /fa` (administrative repair)** coerces execution in **SYSTEM** context. The legacy repair UI spawns Firefox as SYSTEM; **Ctrl+O → `C:\Windows\System32\cmd.exe`** yields an elevated shell.

**Impact:**  
Full local **SYSTEM** compromise — bypass of UAC, SAM/SECURITY hive access, persistence, and potential domain credential extraction if the host were domain-joined. Total loss of host confidentiality, integrity, and availability.

**Proof:**  
`SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r` (held) + `msiexec /fa C:\_install\pdf24-creator-11.15.1-x64.msi` in parallel → legacy Firefox window → Open dialog to `cmd.exe` → `whoami` returned `nt authority\system`. Administrator desktop accessible.

**Recommendation:**  
- **Immediate:** Upgrade or remove PDF24 11.15.1; delete MSI caches from user-reachable paths (`C:\_install`).  
- **Short-term:** Restrict repair rights; harden `Program Files\PDF24` ACLs; monitor `msiexec /fa` from standard users.  
- **Long-term:** Patch SLM for third-party desktop software on servers; application control; remove local admin rights.

**Defensive detection:** EDR rule: standard user → `msiexec /fa` → SYSTEM child process within 60s; oplock/handle anomalies on `faxPrnInst.log`; 4672 special privileges on new logon after Gale session.

---

### Finding 5 — Weak RDP Exposure with Harvestable Saved Credentials (High)

**CVSS v3.1:** 6.8 Medium — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` *(when combined with Finding 3)*  
**MITRE ATT&CK:** T1021.001 · T1133 (External Remote Services)  
**OWASP 2025:** A02 Security Misconfiguration  

**Vector:**  
RDP (3389/tcp) is reachable from the assessment network. Combined with Finding 3, **saved interactive credentials** remove the need for brute force — the attacker decrypts and connects directly as `gale.dekarios`.

**Impact:**  
Direct interactive desktop access to a second user account without credential guessing. Increases blast radius of any foothold on the same host or any machine storing similar connection exports.

**Proof:**  
`nmap` confirmed 3389 open (Microsoft Terminal Services, hostname Lock). Post-decrypt RDP login succeeded without lockout or MFA challenge.

**Recommendation:**  
- **Immediate:** Restrict RDP to jump hosts / management VLAN; disable for non-admin users where not required.  
- **Short-term:** Enforce NLA, MFA (RD Gateway), and account lockout policies.  
- **Long-term:** Just-in-time admin access; no RDP from internet-facing segments.

**Defensive detection:** 4625 failed logons (if brute force attempted); 4624 Type 10 from unexpected source subnets; GeoIP anomalies on 3389.

---

### Finding 6 — Inadequate Gitea Token Lifecycle & Repository Access Controls (High)

**CVSS v3.1:** 7.5 High — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`  
**MITRE ATT&CK:** T1078.004 (Cloud Accounts)  
**OWASP 2025:** A07 Authentication Failures  

**Vector:**  
The leaked PAT retained **read/write access to private repositories** including push/admin rights on `website`. Gitea did not enforce token expiry, scope limitation, or post-leak invalidation after the secret was removed from source. Authenticated enumeration via `/api/v1/user/repos` immediately exposed the full repo inventory.

**Impact:**  
A single long-lived token became the **sole key** to the entire exploit chain — private repo visibility, clone, and production deploy. No secondary control arrested abuse after initial leak.

**Proof:**  
`curl -H "Authorization: token [REDACTED_PAT]" http://lock.htb:3000/api/v1/user/repos` returned private `website` with permissions sufficient for `git push` and CI/CD trigger.

**Recommendation:**  
- **Immediate:** Token revocation and scope audit.  
- **Short-term:** Minimum-scope tokens; 90-day rotation; separate read vs deploy tokens.  
- **Long-term:** OAuth with PKCE; deploy keys with read-only pull on build agents only.

**Defensive detection:** Gitea admin alerts on PAT accessing private repos from new User-Agent/IP; anomalous push frequency; deploy webhook failures/success spikes.

---

### Finding 7 — Lack of Least-Privilege on Web Server Deployment Path (High)

**CVSS v3.1:** 8.8 High — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`  
**MITRE ATT&CK:** T1190 · T1505.003  
**OWASP 2025:** A02 Security Misconfiguration  

**Vector:**  
The CI/CD integration writes directly into the IIS web root with permissions allowing **ASPX execution** under the `ellen.freeman` pool identity. There is no read-only content root, no extension whitelist, and no separation between static asset deploy and executable code paths.

**Impact:**  
Instant code execution from any authenticated push — Finding 2's exploit path requires no additional vulnerability. A document-management-themed public site becomes a **direct RCE surface**.

**Proof:**  
Meterpreter callback confirmed process context `LOCK\ellen.freeman` immediately after first request to git-deployed `rev.aspx` on port 80.

**Recommendation:**  
- **Immediate:** Remove execute permission from upload directories; dedicated app pool with constrained identity.  
- **Short-term:** Deploy static assets only to CDN/static root; run dynamic code in isolated app pools with no write access.  
- **Long-term:** Immutable infrastructure — deploy containers/images, not live file copies to production web root.

**Defensive detection:** App pool identity write events to web root; new executable extensions; Windows Application Event Log ASP.NET errors on unexpected handlers.

---

## Attack Narrative

| Phase | Action | Result |
|-------|--------|--------|
| Recon | `nmap -Pn -sS -sV -sC -p-` | 80/IIS · 445/SMB · 3000/Gitea · 3389/RDP |
| Enum | Gitea `/api/v1/repos/search` | `ellen.freeman/dev-scripts` discovered |
| Cred access | Commit history on `repos.py` | PAT recovered from deleted hardcoded value |
| Auth enum | `/api/v1/user/repos` + PAT | Private `website` repo with push rights |
| Deploy proof | Push `deploy_test.html` | Live on `http://lock.htb/` (CI/CD confirmed) |
| Foothold | Push `rev.aspx` + msf handler | Meterpreter as `ellen.freeman` |
| Post-ex | `net user`, `Documents\config.xml` | Gale target identified; mRemoteNG export found |
| Lateral | Decrypt + `xfreerdp3` | Interactive session as `gale.dekarios` |
| Privesc | SetOpLock + `msiexec /fa` + Firefox | **SYSTEM** shell |
| Impact | Administrator desktop | Full host compromise |

**Total chain length:** 7 hops from unauthenticated external to SYSTEM — no zero-day required.

---

## Human Factors & Operator Observations

Professional assessments include **operator and environmental friction** — errors that did not change the final outcome but would matter on a timed exam or live client retest:

| Observation | Category | Effect | Corrective action |
|-------------|----------|--------|-------------------|
| **`LHOST` bound to `tun0`** with Proton + HTB VPN stacked | Environment | Reverse shell failed to callback | Use `ip route get 10.129.1.185` → bind to **`tun1` src** |
| **`SetOpLock ... -r`** instead of trailing **`r`** | Syntax | Oplock did not attach as intended | Advisory syntax: `SetOpLock.exe "...\faxPrnInst.log" r` |
| **`whoami` in msiexec repair window** | Misread | Showed Gale, not SYSTEM — false negative | SYSTEM only proven in **Firefox-spawned** cmd |
| **Firefox `go.microsoft.com` offline** | Misread | Looked like exploit failure | Offline start page is normal; **Ctrl+O → cmd.exe** is the step |
| **`meterpreter download` to `/tmp/lock-config.xml`** | Tooling | Created directory; decrypt path wrong | Use `/tmp/lock-config.xml/config.xml` or flat file path |
| **Hunted `user.txt` under ellen.freeman** | Objective routing | Wasted time on wrong profile | **`net user`** + mRemoteNG node name → Gale first |
| **`curl` 404 on deploy_test immediately after push** | Timing | Brief false failure | **`sleep 3–10`** or browser confirm before concluding |
| **Initial `curl :3000/login` → 404** | Enum noise | Minor path confusion | Gitea login at `/user/login`; API at `/api/v1/` |
| **Wrong mRemoteNG decrypt repo first tried** | Tooling | Decrypt failed until correct script | **gquere/mRemoteNG_password_decrypt** confirmed working |

These items are **organizational learning**, not client findings — they belong in operator growth notes and purple-team retest planning.

---

## Remediation Roadmap

**Immediate (0–7 days)**  
Revoke Gitea PATs · disable push-to-prod CI/CD · remove webshells from IIS · rotate Ellen and Gale passwords · patch/remove PDF24 11.15.1 · delete `C:\_install` MSI cache · restrict RDP exposure.

**Short-term (7–30 days)**  
Secret scanning in Gitea · staged deploy pipeline with approval · mRemoteNG ban on servers · SMB signing enforced · EDR rules for webshell and `msiexec /fa` chains.

**Long-term (strategic)**  
Zero-trust between dev (Gitea) and prod (IIS) · PAM/vault for all admin creds · immutable deploy model · patch SLM for third-party software on servers.
