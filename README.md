# Threat Hunt Report: Meridian Portal Intrusion

* **Participant:** Chevelle Gauis Dela Cruz
* **Hunt date:** October 3, 2026
* **Incident date:** February 6, 2026 (02:42 to 05:30 UTC)
* **Hunt:** Hunt 25 - Meridian
* **Platform / tools:** Azure Log Analytics Workspace, Kusto Query Language (KQL)
* **Tables used:** `MeridianAccess_CL`, `MeridianAudit_CL`, `MeridianAuth_CL`, `MeridianDefender_CL`, `MeridianSnapshot_CL`

---

## Scenario

A single web application server (Apache, PHP, MySQL) fronting a patient database was intruded on overnight by an external IP, `10.1.134.57`. The host also ran an automated defence suite that logged detections and periodically reverted SSH keys, crontabs and temp directories. Its telemetry sits alongside the attacker's, so much of the task was separating real intrusion artifacts from remediation noise, and stating plainly what the logs do and do not support.

---

## Executive Summary

The attacker enumerated the web server with four tools, then used an unscoped `file` parameter on `config_viewer.php` to read `/etc/passwd` and `database.conf`. 57 seconds after the `database.conf` read, they logged in over SSH as the existing account `svc_backup`, which is consistent with credential reuse from the config file. A `sudo` privilege check failed, but a SUID bash copy (`/tmp/rootbash -p`) gave them root at 04:40:15. The logs do not show how that binary was created. Two bursts of failed SSH logins as `root` came *after* the SUID shell, so the real order was: sudo check, SUID shell, then the failed root logins.

A second SUID foothold, `/opt/meridian/scripts/health_check` (PID 267155), was still running as root in the last snapshot at 05:30:00. Blocked outbound connections to `10.1.134.57:43212` ran from 04:48:28 to 05:02:17. They may come from this binary, but no row ties them to its PID. The defence stack killed and removed the `/tmp` shell, reverted `backup.conf`, and blocked the callbacks. It only **flagged** `health_check`, because that file sits outside everything the sweep remediates, and the block stopped the traffic, not the process. A returning administrator captured memory with AVML. **Killing PID 267155 and removing the file is the one manual action left before the incident can be called contained.**

**Impact:** the defence stack flagged a patient data export from the attacker IP at 03:56:28. This is a detection flag, not confirmed data loss. It is stamped about 1.5 minutes into the directory scan and 11 minutes before the first file read, so it may reflect a web request that matched an export pattern rather than a database dump. Query text and record counts are not in the logs.

Separately, the stack's own bootstrap produced a burst of detections before the first web request, and its first sweep removed `sysmon.service`, which may have reduced visibility for the rest of the incident.

---

## Hunt Findings

### Flag 1 - Reconnaissance Toolchain

**Objective:** Identify how many distinct recon tools hit the web server and in what order.

I grouped HTTP requests from the attacker IP by user agent and looked at first-seen times. User agents can be spoofed, so I treated them as a first pass.

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

| Order | Tool | User agent | First seen | Requests |
|---|---|---|---|---|
| 1 | Nmap | `Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)` | 03:47:32 | 29 |
| 2 | curl | `curl/8.18.0` | 03:52:09 | 16 |
| 3 | WhatWeb | `WhatWeb/0.6.3` | 03:54:54 | 1 |
| 4 | gobuster | `gobuster/3.8.2` | 03:55:05 | 18,454 |

Four more requests with no user agent (`-`) start in the same second as Nmap, so they are most likely Nmap's own probes and not a fifth tool. Counts cover the whole window.

**MITRE:** T1595 (Active Scanning)

---

### Flag 2 - The Traversal Point

**Objective:** Find the one endpoint the attacker touched deliberately before the wordlist scan.

I listed every curl request before the first gobuster request. The curl requests look manual (few, spaced out, no wordlist pattern), and one stood out as a non-default application page.

```kql
let start = datetime(2026-02-06 02:42:00);
let end = datetime(2026-02-06 03:55:05);
MeridianAccess_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where ClientIp_s == "10.1.134.57" and UserAgent_s startswith "curl"
| project EventTime_t, RequestUri_s, StatusCode_s, UserAgent_s
| order by EventTime_t asc
```
<img width="698" height="272" alt="image" src="https://github.com/user-attachments/assets/81cd650f-600a-427c-b4cd-72035fb111c8" />

**Finding:** `config_viewer.php`, a single `curl/8.18.0` request at 03:52:29, about 2.5 minutes before gobuster started at 03:55:05. It returned **302**, a redirect, so this first touch did not return the page. The logs do not show where it redirected to. The later file reads (Flag 3) returned 200. The logs show the endpoint was requested directly before wordlist scanning began. They do not prove the attacker had prior knowledge of it.

**MITRE:** T1190 (Exploit Public-Facing Application)

---

### Flag 3 - Files Read Through the `file` Parameter

**Objective:** Identify the two files read through the unscoped parameter, in order.

I listed every request from the attacker IP between 04:00 and 04:10, the ten minutes before the SSH login.

```kql
let start = datetime(2026-02-06 04:00:00);
let end = datetime(2026-02-06 04:10:00);
MeridianAccess_CL
| where isnotempty(EventTime_t) and EventTime_t between (start .. end)
| where ClientIp_s == "10.1.134.57"
| project EventTime_t, RequestUri_s, StatusCode_s, UserAgent_s
| order by EventTime_t asc
```

<img width="856" height="188" alt="image" src="https://github.com/user-attachments/assets/0a7b2501-2f75-4eb0-b6da-b3f09749ae6e" />

**Finding:** `/etc/passwd` (04:07:59, 200), then `database.conf` (04:08:34, 200). The first request climbs out of the web directory with `../../../`. The second names a file directly. A `/dashboard.php` 200 at 04:07:47 fits an authenticated session, but the login request itself was not seen.

**Evidence limit:** both requests returned 200, but the logs do not show what the files contained. `/etc/passwd` holds account names, not password hashes.

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

**Finding:** `svc_backup` logged in from `10.1.134.57` at 04:09:31, 57 seconds after `database.conf` was read, using a password and not a key. The query returns five accepted logins in total:

| Time | User | Source | Reading |
|---|---|---|---|
| 02:48:41 | `root` | 10.1.134.57 | Before any web activity and not part of the config-read chain. This query does not show what it did. |
| 02:56:33 | `svc_backup` | 127.0.0.1 | Local login in the setup window. Not attacker activity. |
| 04:09:31 | `svc_backup` | 10.1.134.57 | The main finding. |
| 04:47:44 | `svc_backup` | 10.1.134.57 | Repeat login, 52 seconds after the root failures in Flag 5. |
| 04:48:28 | `svc_backup` | 10.1.134.57 | Repeat login, same second as the first blocked callback. Its source port (43212) equals the C2 port number. I cannot tell whether that is coincidence, so I do not rely on it. |

**Evidence limits:** the 04:09:31 login is consistent with credential reuse from the config file, but the logs do not show where the password came from.

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

1. **sudo privilege check:** at 04:15:07, `svc_backup : command not allowed ; USER=root ; COMMAND=list`. The account has no sudo rights. `COMMAND=list` indicates `sudo -l`, but Audit did not record the command, so that part is inferred. The other sudo rows belong to the `ubuntu` admin (Flags 13 and 15).
2. **Direct root SSH login:** two bursts of `Failed password for root`, one from `10.1.15.67` (the host itself, 04:44:25 to 04:44:59) and one from `10.1.134.57` (04:45:39 to 04:46:52). Each burst ends in `Connection closed by authenticating user root ... [preauth]`.

**Evidence limits:** the burst from `10.1.15.67` is probably the attacker working from inside the `svc_backup` session, but no row proves it. The logs cannot separate a wrong password from a disabled setting.

**Ordering:** these SSH attempts came after the SUID shell at 04:40:15, so they are further attempts, not attempts made before escalation.

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

**Evidence limit:** Audit records the execution but not how the binary was created or made SUID.

**MITRE:** T1548.001 (Setuid and Setgid)

---

### Flag 7 - The Second Foothold

**Objective:** Identify the second, better-hidden SUID foothold.

Audit held nothing for this one, even after searching `Argv_s`, `exe_s` and `name_s`. The evidence is in the Snapshot table.

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
| Snapshot time | 05:30:00 (process still present at the end of the data) |
| Name | `health_check` |
| Exe link | `/proc/267155/exe -> /opt/meridian/scripts/health_check` |
| PID / PPid | 267155 / 1 (orphaned) |
| UIDs (real/effective/saved/fs) | 1001 / 0 / 0 / 0 |
| `/proc` link timestamp | Feb 6 04:51 (approximate, not necessarily the start time) |

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

The sweep reverts SSH keys, crontabs and `backup.conf`, and cleans temp directories and processes running from them. `/opt/meridian/scripts/health_check` is none of those, so it was detected but never remediated. This is a **detection-versus-remediation gap**. The previous sweep (04:29:51) ran before both the shell and `health_check`, so 05:05 was the first sweep that could have seen either.

**MITRE:** T1564.001 (Hidden Files and Directories)

---

### Flags 9 and 10 - Calling Home, and What the Block Proves

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

**Finding:** repeated `Blocked exfil to 10.1.134.57:43212 from 10.1.15.67`: 73 blocked attempts, first at 04:48:28 and last at 05:02:17.

* **The block proves:** outbound connections to `10.1.134.57:43212` were intercepted and dropped from that point on.
* **The block does not prove:** that the process is stopped, the binary removed, or the host contained. `health_check` was still present in the 05:30:00 snapshot.

**Evidence limits:** no row ties the blocked connections to PID 267155, so the link is by timing and the shared host. The first block is about 2.5 minutes before the 04:51 `/proc` timestamp, which weakens the link a little. Whether any connection succeeded before the block took effect is not shown.

**MITRE:** T1071 (Application Layer Protocol)

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

**Finding:** patient records. The flag reads `Patient data export from 10.1.134.57` at 03:56:28. A separate `DB: Full patient table query` line at 02:58:26 predates all attacker web activity and has no source IP, so I treat it as defence noise, not collection.

**Evidence limits:** this is a defence flag in the `WEB` category, stamped about 1.5 minutes into the gobuster scan and 11 minutes before the first file read, before the attacker had shown any credentials. It may reflect a web request that matched an export pattern, not a database dump. Exact queries and record counts are not in the logs, and the blocked connections show an attempt to send data, not confirmed data loss.

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

**Evidence limits:** the logs do not show who changed it or what changed. It is probably the attacker or their backdoor, which fits the `svc_backup` account name but is not proven. The original content is gone after the revert.

**MITRE:** T1565.001 (Stored Data Manipulation)

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

**Finding:** false positive / setup noise. Eight `DETECTION` rows at 02:53:31 to 02:53:32 (crontab and SSH key modifications marked "reverting", plus two `New systemd service detected`) come well before the first web request. None carries a source IP, and the stack reverted them automatically. The setup reading is supported by the `ubuntu` admin's root session opened at 02:43:19 (a root session closes at 03:21:19, presumably the same one) and by a local `svc_backup` login from 127.0.0.1 at 02:56:33.

**MITRE:** T1036 (Masquerading)

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

**Finding:** the first sweep (03:08:17) removed `sysmon.service` at 03:08:20. A separate `Removed service: 60` line at 03:08:19 is unexplained. Removing the host's telemetry service about 39 minutes before the first attacker web request is consistent with the later gaps, such as no record of how the SUID binaries were staged.

**Evidence limit:** the logs show the removal, not what Sysmon would have captured. Some gaps may instead come from auditd rule coverage.

**MITRE:** T1562.001 (Impair Defenses)

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

**Finding:** AVML (`/tmp/avml`) ran twice with the same arguments, at 05:27:48 and 05:28:24, writing to `/tmp/evidence/memory.lime`. The auid of 1000 matches the `ubuntu` account, which ran `sudo /bin/bash` at 05:23:01. This is the responder, not the attacker. AVML is Microsoft's open-source Linux memory-acquisition tool, and running it before touching `health_check` is the right forensic order.

**Evidence limit:** Audit shows the command lines, not whether the image was written successfully.

**MITRE:** T1005 (Data from Local System)

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

**Finding:** Defender's only row mentioning `health_check` is the 05:05:06 flag, so the stack never remediated it, and the Snapshot row from Flag 7 shows PID 267155 still present at 05:30:00. The action needed is to manually kill PID 267155 and remove `/opt/meridian/scripts/health_check`. Memory was already captured, so terminating the process no longer destroys volatile evidence.

---

## Attacker Versus Defence Noise

| Artifact | First seen | Actor | Attacker-linked? | Verdict |
|---|---|---|---|---|
| `ubuntu` root session | 02:43:19 | Admin / setup | No | Setup |
| Install-time detection burst | 02:53:31 | Defence stack | No source IP | Defence noise |
| `svc_backup` login from 127.0.0.1 | 02:56:33 | Local / setup | No | Defence noise |
| `DB: Full patient table query` | 02:58:26 | Defence stack | No source IP | Defence noise |
| `sysmon.service` removal | 03:08:20 | Sweep | No | Defence noise (collateral) |
| `Patient data export` flag | 03:56:28 | Defence flag on attacker IP | Yes (source IP) | Attacker-linked flag, content unverified |
| `/tmp/rootbash` | 04:40:15 | `svc_backup` | Yes | Attacker, removed 05:05 |
| Blocked connections to 10.1.134.57:43212 | 04:48:28 | Backdoor (probable) | Yes | Attacker, blocked not stopped |
| `health_check` | about 04:51 | `svc_backup` (probable) | Probable | Attacker, survived |
| `backup.conf` tamper | 05:05:02 | Not identified | Unclear | Unclear, reverted |
| `ubuntu` root sudo, AVML | 05:23:01 to 05:28:24 | Returning admin | No | Responder |

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Attacker IP | `10.1.134.57` | Source of all attacker web and SSH activity |
| C2 destination | `10.1.134.57:43212` | 73 blocked outbound connections from 10.1.15.67, 04:48:28 to 05:02:17 |
| Recon tools | Nmap, curl, WhatWeb, gobuster | `curl/8.18.0`, `WhatWeb/0.6.3`, `gobuster/3.8.2`, Nmap NSE |
| Vulnerable endpoint | `/config_viewer.php` (`file` parameter) | Unscoped file read |
| Files read | `/etc/passwd`, `database.conf` | 04:07:59 and 04:08:34 |
| Compromised account | `svc_backup` (uid 1001) | Attacker-IP logins at 04:09:31, 04:47:44, 04:48:28 |
| Escalation binary (removed) | `/tmp/rootbash -p` | Executed 04:40:15, removed 05:05 |
| Persistence binary (live) | `/opt/meridian/scripts/health_check` (PID 267155) | Flagged only, still present at 05:30:00 |
| Tampered file | `backup.conf` | Reverted 05:05:02 |
| Responder artifact | `/tmp/evidence/memory.lime` | AVML output from the returning admin, not an attacker indicator |

---

## Lessons Learned

1. **Separate attacker activity from defence-stack output.** Timing, source IP, and whether an artifact was an addition or a revert were the most useful tests.
2. **Detection is not remediation.** The sweep killed the `/tmp` shell, but `health_check` was flagged in plain sight and left running. The network block had the same limit: it stopped the callbacks, not the process.
3. **The data dictionary was not the whole schema.** Audit had undocumented columns, and the second foothold's evidence lived in Snapshot, not Audit. Run `getschema` early, and try another table when a query comes back empty.
