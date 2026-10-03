# Threat Hunt Report: Meridian Portal Intrusion
 
* **Participant:** Chevelle Gauis Dela Cruz
* **Hunt date:** October 3, 2026
* **Incident date:** February 6, 2026 (02:42 to 05:30 UTC)
* **Hunt:** Hunt 25 - Meridian
 
---
 
## Platforms and Tools Utilized
 
**Platforms:**
 
* Azure Log Analytics Workspace
 
**Languages/Tools:**
 
* Kusto Query Language (KQL)
 
**Tables used:** `MeridianAccess_CL`, `MeridianAudit_CL`, `MeridianAuth_CL`, `MeridianDefender_CL`, `MeridianSyslog_CL`, `MeridianSnapshot_CL`, `MeridianNetwork_CL`, `MeridianMySQL_CL`
 
---
 
## Scenario
 
A single web application server (Apache, PHP, MySQL) fronting a patient database was intruded on overnight by an external IP, `10.1.134.57`. The host also ran a six-service automated defence suite that logged detections and periodically reverted SSH keys, crontabs and temp directories. That stack produced its own telemetry alongside the attacker's, so a large part of the task was separating real intrusion artifacts from automated remediation noise, and stating plainly what the logs do and do not support.
 
---
 
## Executive Summary
 
The attacker enumerated the web server with four tools, then used an unscoped `file` parameter on `config_viewer.php` to read `/etc/passwd` and `database.conf`. 57 seconds after the `database.conf` read they logged in over SSH as the existing account `svc_backup`. A `sudo` privilege check failed, but a pre-staged SUID bash copy (`/tmp/rootbash -p`) gave them root. They later had a second SUID foothold, `/opt/meridian/scripts/health_check`, which kept trying to call out to `10.1.134.57:43212`.
 
The automated defence stack killed and removed the `/tmp` shell, reverted `backup.conf`, and blocked the outbound callbacks. It only **flagged** `health_check`, because that file sits outside everything the sweep remediates. The block stopped the network traffic but not the process. A returning administrator captured memory with AVML. At the end of the data, **`health_check` has still not been killed or removed**, and that is the one manual action left before the incident can be called contained.
 
Separately, the stack's own bootstrap produced a burst of detections before the attacker arrived, and its first sweep removed `sysmon.service`, which reduced visibility for the rest of the incident.
 
---
 
## Hunt Findings
 
### Flag 1 - Reconnaissance Toolchain
 
**Objective:** Identify how many distinct recon tools hit the web server and in what order.
 
I grouped all HTTP requests by user agent and looked at first-seen times, then confirmed which user agents belonged to the attacker IP. User agents can be spoofed, so I treated them as a first pass.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianAccess_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where ClientIp_s == "10.1.134.57"
| summarize FirstSeen=min(EventTime_t), Requests=count() by UserAgent_s
| order by FirstSeen asc
```
 <img width="1547" height="220" alt="image" src="https://github.com/user-attachments/assets/8b3d536b-f38e-409f-813a-4af4ff7f80d2" />

 
**Finding:** four tools, in order of first appearance:
 
| Order | Tool | User agent | First seen |
|---|---|---|---|
| 1 | Nmap | `Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)` | 03:47:32 |
| 2 | curl | `curl/8.18.0` | 03:52:09 |
| 3 | WhatWeb | `WhatWeb/0.6.3` | 03:54:54 |
| 4 | gobuster | gobuster | 03:55:05 |
 
The platform reports roughly 18,454 gobuster requests. `[confirm the count from your own output]`.
 
**MITRE:** T1595 (Active Scanning)
 
---
 
### Flag 2 - The Traversal Point
 
**Objective:** Find the one endpoint the attacker touched deliberately before the wordlist scan.
 
I listed every request before the first gobuster request, one row per path and user agent. Nmap's rows were scripted probes (`/.git/HEAD`, `/HNAP1`, `/sdk` and similar). The curl rows were hand-typed, and one stood out as a non-default application page.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 03:55:00);
MeridianAccess_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where ClientIp_s == "10.1.134.57"
| where RequestUri_s has "config"
| project EventTime_t, RequestUri_s, StatusCode_s, UserAgent_s
```
 <img width="666" height="105" alt="image" src="https://github.com/user-attachments/assets/f7b93831-631e-491a-9787-b2169b06f7b5" />

 
**Finding:** `config_viewer.php`, a single `curl/8.18.0` request at 03:52:29, about 2.5 minutes before gobuster started at 03:55:05.
 
**Note on wording:** the logs show the endpoint was requested directly before wordlist scanning began. They do not prove the attacker had prior knowledge of it.
 
**MITRE:** T1190 (Exploit Public-Facing Application)
 
---
 
### Flag 3 - Files Read Through the `file` Parameter
 
**Objective:** Identify the two files read through the unscoped parameter, in order.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianAccess_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where ClientIp_s == "10.1.134.57"
| where RequestUri_s has "config_viewer" and RequestUri_s has "file="
| project EventTime_t, RequestUri_s, StatusCode_s, ResponseSize_s
| order by EventTime_t asc
```
 **Finding:**

<img width="820" height="133" alt="image" src="https://github.com/user-attachments/assets/645bb7b8-34cb-4749-ab74-1b43a3d9ee80" />

 
The first request climbs out of the web directory with `../../../`. The second names a file directly. A `/dashboard.php` 200 at 04:07:47 fits an authenticated session, but the login request itself was not seen.
 
**Evidence limit:** the logs show both requests returned content. They do not show what the files contained. `/etc/passwd` holds account names but not password hashes.
 
**MITRE:** T1552.001 (Credentials In Files)
 
---
 
### Flag 4 - Borrowed Access
 
**Objective:** Identify the existing account used to log in over SSH shortly after the config read.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianAuth_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where RawMessage_s has "Accepted password"
| project EventTime_t, SourceIP, TargetUser_s, RawMessage_s
| order by EventTime_t asc
```
 
<img width="872" height="225" alt="image" src="https://github.com/user-attachments/assets/2f06b44c-00b7-4eab-85bd-6a7b068737f7" />

 
**Finding:** `svc_backup` logged in from `10.1.134.57` at 04:09:31 (port 39206, session 7), 57 seconds after `database.conf` was read. It authenticated with a password, not a key.
 
**Evidence limit:** this is consistent with credential reuse from the config file, but the logs do not show where the password came from. The exact credentials remain a gap.
 
**MITRE:** T1078 (Valid Accounts)
 
---
 
### Flag 5 - Failed Root Attempts
 
**Objective:** Identify two other ways the attacker tried to get root, and why each failed.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianAuth_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where ProcessName_s in~ ("sudo", "su")
| project EventTime_t, ProcessName_s, TargetUser_s, RawMessage_s
| order by EventTime_t asc
```
 
```kql
let start = datetime(2026-02-06 04:43:00);
let end = datetime(2026-02-06 04:48:00);
MeridianAuth_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| project EventTime_t, ProcessName_s, SourceIP, TargetUser_s, RawMessage_s
| order by EventTime_t asc
```
 
<img width="977" height="240" alt="image" src="https://github.com/user-attachments/assets/4c6d2879-189e-41d3-9281-d4ef04475f82" />

 
<img width="1496" height="353" alt="image" src="https://github.com/user-attachments/assets/87af5dc2-c86f-496e-abc9-d8976df5abd4" />

 
**Finding:**
 
1. **sudo privilege check:** at 04:15:07, `svc_backup : command not allowed ; USER=root ; COMMAND=list`. The account has no sudo rights. `COMMAND=list` indicates `sudo -l`, but Audit did not record the command, so that part is inferred.
2. **Direct root SSH login:** at 04:44:25 to 04:46:52, `Failed password for root`. Auth shows three failures per burst (one plus "repeated 2 times"), one burst from `10.1.15.67` (the host itself) and one from `10.1.134.57`. Defender summarises each burst as two attempts.
 
**Evidence limits:** the logs cannot separate a wrong password from root password login being disabled. The burst from 10.1.15.67 is probably the attacker working from inside the `svc_backup` session, but no row proves it.
 
**Ordering note:** these SSH attempts came after the SUID shell at 04:40:15, so they are further attempts, not attempts made before escalation.
 
**MITRE:** T1078 (Valid Accounts)
 
---
 
### Flag 6 - The Planted Root Shell
 
**Objective:** Identify the SUID binary used for privilege escalation, with its flag.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianAudit_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where Types_s has "EXECVE"
| where Argv_s has "rootbash"
| project EventTime_t, comm_s, exe_s, Argv_s, auid_s, euid_s
```

<img width="967" height="106" alt="image" src="https://github.com/user-attachments/assets/a5444776-5727-4fb7-a678-a17e9566f0ff" />

 
**Finding:** `/tmp/rootbash -p` ran at 04:40:15 with `auid=1001` (`svc_backup`) and `euid=0`. The `-p` flag stops bash from dropping the SUID privilege.
 
**Evidence limit:** Audit records the execution but not how the binary was created or made SUID. That is the "how the first backdoor was staged" gap.
 
**MITRE:** T1548.001 (Setuid and Setgid)
 
---
 
### Flag 7 - The Second Foothold
 
**Objective:** Identify the second, better-hidden SUID foothold.
 
Audit held nothing for this one, even after searching `Argv_s`, `exe_s` and the `name_s` column. The evidence is in the Snapshot table.
 
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianSnapshot_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where isnotempty(ProcBeaconExeLink_s)
| project EventTime_t, ProcBeaconName_s, ProcBeaconExeLink_s, ProcBeaconPid_s, ProcBeaconPPid_s, ProcBeaconUid_s, ProcessTreeSnapshot_s
| order by EventTime_t asc
```
 
<img width="1392" height="98" alt="image" src="https://github.com/user-attachments/assets/6bf54c84-ba2b-4a1f-a049-788d46dfaa8d" />

 
**Finding:**
 
| Field | Value |
|---|---|
| Name | `health_check` |
| Exe link | `/proc/267155/exe -> /opt/meridian/scripts/health_check` |
| PID | 267155 |
| PPid | 1 (orphaned) |
| UIDs (real/effective/saved/fs) | 1001 / 0 / 0 / 0 |
| `/proc` link timestamp | Feb 6 04:51 (approximate) |
 
Real UID 1001 with effective UID 0 is consistent with a SUID-root binary run by `svc_backup`. The name and location blend into the application's own scripts folder.
 
**Evidence limits:** the row has no source IP or session, so the link to the attacker is circumstantial. How the file got there and became SUID is not logged.
 
**MITRE:** T1036.005 (Match Legitimate Name or Location)
 
---
 
### Flag 8 - Why `health_check` Survived the Sweep
 
**Objective:** Explain what the sweep cleans up automatically and why this file fell outside it.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianDefender_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where EventCategory_s == "SWEEP"
| project EventTime_t, RawMessage_s
| order by EventTime_t asc
```
 
<img width="1225" height="498" alt="image" src="https://github.com/user-attachments/assets/f1d34de1-c064-42a4-867a-7fbbc2698e66" />

 
**Finding:** at 05:05 the sweep:
 
* killed `PID=265440 from /tmp (/tmp/rootbash -p)`
* reverted `backup.conf`
* logged `Non-baseline file in scripts/: health_check` (flag only)
* ran `Temp dirs cleaned` and `Removed SUID: /tmp/rootbash`
 
The sweep reverts SSH keys, crontabs and `backup.conf`, and cleans temp directories and processes running from them. `/opt/meridian/scripts/health_check` is none of those, so it was detected but never remediated. This is a **detection-versus-remediation gap**.
 
**Note:** the platform lists SUID files in watched paths and systemd services as further sweep categories. Only the categories above were seen in our rows.
 
**MITRE:** T1564.001 (Hidden Files and Directories), per the platform
 
---
 
### Flag 9 - Calling Home
 
**Objective:** Identify the destination the backdoor kept hitting and whether the block neutralised it.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianDefender_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where EventCategory_s == "NETWORK" and DestIp_s == "10.1.134.57"
| summarize Hits=count(), First=min(EventTime_t), Last=max(EventTime_t) by DestPort_s
```
 
<img width="842" height="107" alt="image" src="https://github.com/user-attachments/assets/63892bd1-2f39-4385-82aa-cd7d4b82755c" />

 
**Finding:** repeated `Blocked exfil to 10.1.134.57:43212 from 10.1.15.67`, first at 04:48:28 with a further block at 05:02:17. The platform reports 73 blocked attempts in total `[confirm the count from your own summarise output]`. The block did not neutralise the threat: it stopped the connection, not the process.
 
**Evidence limit:** no row ties the blocked connections to PID 267155. The link is by timing and the shared host.
 
**MITRE:** T1071 (Application Layer Protocol)
 
---
 
### Flag 10 - What the Network Block Does and Does Not Prove
 
**Finding:**
 
* **Proves:** outbound connections to `10.1.134.57:43212` were intercepted and dropped, so the callbacks did not complete from the block onward.
* **Does not prove:** that the process is stopped, that the binary is removed, or that the host is contained. `health_check` still existed after the block and would resume if the block were lifted.
 
**Evidence limit:** whether any connection succeeded before the block took effect is not shown.
 
---
 
### Flag 11 - What Left the Database
 
**Objective:** Identify the type of data the defence stack flagged as exported.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianDefender_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where EventCategory_s == "WEB" and RawMessage_s has "export"
| project EventTime_t, SourceIP, RawMessage_s
```
 
<img width="820" height="102" alt="image" src="https://github.com/user-attachments/assets/e25499aa-a211-4de1-9a10-5051b987a194" />

 
**Finding:** patient records. The flag reads `Patient data export from 10.1.134.57` at `[time from your output]`.
 
A `DB: Full patient table query` line at about 02:58 predates all attacker activity and is classed as defence noise, not collection.
 
**Evidence limits:** this is a defence flag. The exact export queries and record counts are not in the logs. The blocked outbound connections show an attempt to send data, not data loss.
 
**MITRE:** T1213 (Data from Information Repositories)
 
---
 
### Flag 12 - The Tampered File
 
**Objective:** Identify the config file the final sweep reverted.
 
```kql
let start = datetime(2026-02-06 05:04:00);
let end = datetime(2026-02-06 05:30:00);
MeridianDefender_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where EventCategory_s == "SWEEP" and RawMessage_s has "tampered"
| project EventTime_t, RawMessage_s
```
 
<img width="463" height="105" alt="image" src="https://github.com/user-attachments/assets/299a9def-0626-4b47-a50d-40345d4e953a" />

 
**Finding:** `backup.conf`, reverted at 05:05:02.
 
**Evidence limits:** the logs do not show who changed it or what changed. The platform attributes it to the attacker or their backdoor, which fits the `svc_backup` account name but is not proven. The original tampered content is gone after the revert.
 
**MITRE:** T1565.001 (Stored Data Manipulation), per the platform
 
---
 
### Flag 13 - Signal or Setup Noise
 
**Objective:** Decide whether the burst of detections before the intrusion belongs to the attacker.
 
```kql
let start = datetime(2026-02-06 02:00:00);
let end = datetime(2026-02-06 03:47:32);
MeridianDefender_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| project EventTime_t, EventCategory_s, SourceIP, RawMessage_s
| order by EventTime_t asc
```
 
<img width="1093" height="517" alt="image" src="https://github.com/user-attachments/assets/cb40db33-54bd-4ddf-80b3-120bab618c82" />

 
**Finding:** false positive / setup noise. The burst (platform time 02:53:31 `[confirm]`) comes well before the first attacker request, is not linked to `10.1.134.57`, and is reverted automatically. It is consistent with the defence stack's own installation tripping its detections.
 
---
 
### Flag 14 - Collateral Damage
 
**Objective:** Identify the legitimate service the first sweep removed and what it cost.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 03:10:00);
MeridianDefender_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where EventCategory_s == "SWEEP" and RawMessage_s has "Removed service"
| project EventTime_t, RawMessage_s
```
 
<img width="517" height="127" alt="image" src="https://github.com/user-attachments/assets/bc626049-0030-4063-aedd-64302e93339c" />

 
**Finding:** the first sweep removed `sysmon.service` (our rows show 03:08:20, the platform says 03:08:19) as a new systemd service. A separate `Removed service: 60` line appears at 03:08:19 and is unexplained. Removing the host's telemetry service about 39 minutes before the first attacker request is consistent with the gaps seen later, such as no record of how the SUID binaries were staged.
 
**Evidence limit:** the logs show the removal, not what Sysmon would have captured. Some gaps may instead come from auditd rule coverage.
 
**MITRE:** T1562.001 (Impair Defenses), per the platform
 
---
 
### Flag 15 - Capturing the Evidence
 
**Objective:** Identify how the returning administrator captured volatile state.
 
```kql
let start = datetime(2026-02-06 05:20:00);
let end = datetime(2026-02-06 05:30:00);
MeridianAudit_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where Types_s has "EXECVE"
| where Argv_s has "avml" or comm_s has "avml"
| project EventTime_t, comm_s, exe_s, Argv_s, auid_s, euid_s
```
 
<img width="922" height="135" alt="image" src="https://github.com/user-attachments/assets/47601768-6bc6-4bf1-afc5-0b7dad37eb18" />

 
**Finding:** AVML (`/tmp/avml`) ran twice with the same arguments, at 05:27:48 and 05:28:24, writing to `/tmp/evidence/memory.lime`. The auid of 1000 matches the `ubuntu` account, which logged in by key from 10.0.2.139 at 05:22:56 and ran `sudo /bin/bash` at 05:23:01. This sequence is classed as the responder, not the attacker.
 
**Evidence limits:** Audit shows the command lines, not whether the image was written successfully. The image sits in `/tmp`, which the sweep cleans, though no sweep appears after 05:05 in our rows.
 
---
 
### Flag 16 - What Is Still Live
 
**Objective:** State the one manual action needed before the incident can be called contained.
 
```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 05:30:00);
MeridianDefender_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where RawMessage_s has "health_check"
| project EventTime_t, EventCategory_s, RawMessage_s
```
 
<img width="792" height="100" alt="image" src="https://github.com/user-attachments/assets/21893059-8821-4519-b7fc-e80974ddfec9" />

 
**Finding:** manually kill PID 267155 and remove `/opt/meridian/scripts/health_check`. The sweep killed `/tmp/rootbash`, reverted `backup.conf`, and the administrator captured memory, but `health_check` was only ever flagged. Memory was captured before this step, so terminating the process no longer destroys volatile evidence.
 
---
 
## Attacker Versus Defence Noise
 
| Artifact | First seen | Actor | Attacker-linked? | Reverted? | Verdict |
|---|---|---|---|---|---|
| Install-time detection burst | 02:53:31 `[confirm]` | Defence stack | No | Yes, automatically | Defence noise |
| `DB: Full patient table query` | about 02:58 `[confirm]` | Defence stack | No | n/a | Defence noise |
| `sysmon.service` removal | 03:08:20 | Sweep | No | n/a | Defence noise (collateral) |
| Root CRON open/close pairs | throughout | cron | No | n/a | Scheduled noise |
| `/tmp/rootbash` | 04:40:15 | `svc_backup` | Yes | Yes, 05:05 | Attacker |
| `health_check` | about 04:51 | `svc_backup` (probable) | Probable | No | Attacker, survived |
| Blocked connections to 10.1.134.57:43212 | 04:48:28 | Backdoor (probable) | Yes | Blocked, not stopped | Attacker |
| `backup.conf` tamper | 05:05:02 | Not identified | Unclear (platform: attacker or backdoor) | Yes | Unclear |
| `ubuntu` key login, root sudo, AVML | 05:22:56 to 05:28:24 | Returning admin | No | n/a | Responder |
 
---
 
## Summary of Findings
 
| Flag | Question | Answer | Source |
|---|---|---|---|
| 1 | Recon tools, in order | 4: Nmap, curl, WhatWeb, gobuster | Access |
| 2 | Traversal point | `config_viewer.php` | Access |
| 3 | Files read | `etc/passwd, database.conf` | Access |
| 4 | SSH account used | `svc_backup` | Auth |
| 5 | Failed root attempts | `sudo -l` not allowed; root SSH password failed | Auth, Defender |
| 6 | SUID root shell | `/tmp/rootbash -p` | Audit |
| 7 | Second SUID foothold | `/opt/meridian/scripts/health_check` | Snapshot |
| 8 | Why it survived | Outside sweep remediation scope; flagged only | Defender |
| 9 | C2 destination | `10.1.134.57:43212`, block did not neutralise it | Defender |
| 10 | What the block proves | Callbacks blocked; process not stopped | Defender, Snapshot |
| 11 | Data exported | Patient records | Defender |
| 12 | Config tampered | `backup.conf` | Defender |
| 13 | Pre-intrusion burst | False positive / setup noise | Defender |
| 14 | Collateral damage | `sysmon.service` | Defender |
| 15 | Volatile capture | AVML to `/tmp/evidence/memory.lime` | Audit |
| 16 | Remaining manual action | Kill PID 267155 and remove `health_check` | Defender, Snapshot |
 
---
 
## Indicators of Compromise
 
| Type | Value | Notes |
|---|---|---|
| Attacker IP | `10.1.134.57` | Source of all attacker web and SSH activity |
| C2 destination | `10.1.134.57:43212` | Blocked outbound connections from 10.1.15.67 |
| Recon tools | Nmap, curl, WhatWeb, gobuster | User agents: Nmap NSE, `curl/8.18.0`, `WhatWeb/0.6.3`, gobuster |
| Vulnerable endpoint | `/config_viewer.php` (`file` parameter) | Unscoped file read |
| Files read | `/etc/passwd`, `database.conf` | Read at 04:07:59 and 04:08:34 |
| Compromised account | `svc_backup` (uid 1001) | Pivot account, logged in at 04:09:31 |
| Failed escalation attempts | `sudo -l` (command not allowed); SSH login as `root` (password authentication failed) | Pivot activity |
| Escalation binary (removed) | `/tmp/rootbash -p` | Executed 04:40:15, removed by the sweep at 05:05 |
| Persistence binary (live) | `/opt/meridian/scripts/health_check` (PID 267155) | Flagged only, never remediated |
| Data targeted | Patient records | Flagged by Defender as exported |
| Tampered file | `backup.conf` | Reverted by the sweep at 05:05:02 |
| Responder artifact | `/tmp/evidence/memory.lime` | AVML output from the returning admin, not an attacker indicator |
 
---
 
## MITRE ATT&CK Mapping
 
| Technique | ID | Flag |
|---|---|---|
| Active Scanning | T1595 | 1 |
| Exploit Public-Facing Application | T1190 | 2 |
| Credentials In Files | T1552.001 | 3 |
| Valid Accounts | T1078 | 4, 5 |
| Setuid and Setgid | T1548.001 | 6 |
| Match Legitimate Name or Location | T1036.005 | 7, 16 |
| Hidden Files and Directories | T1564.001 | 8 |
| Application Layer Protocol | T1071 | 9, 10 |
| Data from Information Repositories | T1213 | 11 |
| Stored Data Manipulation | T1565.001 | 12 |
| Masquerading | T1036 | 13 |
| Impair Defenses: Disable or Modify Tools | T1562.001 | 14 |
| Data from Local System | T1005 | 15 |
 
*Mappings follow the hunt platform. Flags 13 and 15 describe defence-stack noise and responder activity, not attacker actions, so T1036 and T1005 there are the platform's labels for the data, not an attacker technique.*
  
---
 
## Lessons Learned
 
Separating attacker activity from the defence stack's own output was the core skill in this hunt. The pre-contact detection burst and the first sweep's removal of `sysmon.service` both predate any attacker request, and treating them as intrusion indicators would have been a triage error. Timing against the first attacker request, source IP, and whether the artifact was an addition or a revert were the most useful tests.
 
The second lesson is that detection is not remediation. The sweep killed and removed the `/tmp` shell, but `health_check` was flagged in plain sight and left running because it sat outside every category the sweep acts on. The network block had the same limit: it stopped the callbacks but not the process behind them.
 
Third, the data dictionary was not the whole schema. The Audit table had extra columns (`name_s`, `cwd_s`, `item_s`) that were not documented, and the evidence for the second foothold lived in the Snapshot table, not Audit. Running `getschema` early and trying a different table when a query came back empty saved time.
 
Finally, the platform's explanations sometimes went further than the rows did, for example on credential reuse, beacon "backoff" and the effect of Sysmon's removal. Each of those is written here as consistent with the evidence, with the gaps stated, and every count or timestamp that came only from the platform is marked for confirmation against real query output.
