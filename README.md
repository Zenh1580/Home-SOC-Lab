# Home SOC Lab: Detecting & Investigating Web Attacks with Wazuh

**Author:** Zen

A hands-on home Security Operations Center (SOC) lab built to practice the core blue-team workflow: collecting logs, detecting attacks with a SIEM, and investigating alerts the way a SOC analyst does. This project documents how I built the lab, generated attacks against a controlled target, and — most importantly — how I triaged a critical-severity alert to separate a real threat from scanner noise.

---

## Overview

The goal of this lab was to understand the full **attack → detect → investigate** loop end to end, using free and open-source tooling. Rather than just installing a SIEM, I wanted to generate real attack traffic against a target I own and then work the resulting alerts like an analyst on shift — deciding what matters, what doesn't, and why.

**Key skills demonstrated:**
- Deploying and configuring a SIEM (Wazuh) from scratch
- Onboarding a log source and validating the detection pipeline
- Generating attack traffic to test detection coverage
- Triaging and investigating alerts (severity vs. impact, attempt vs. success)
- Mapping activity to the MITRE ATT&CK framework

---

## Architecture

The lab runs entirely on a single laptop using virtualization, on an isolated network so no traffic leaves the environment.

```
          ┌─────────────────────────────────────────────┐
          │                Host (Windows)                │
          │                                              │
          │   ┌──────────────────────────────────────┐   │
          │   │         Kali Linux VM (isolated)     │   │
          │   │                                      │   │
          │   │   ┌────────────┐     ┌────────────┐  │   │
          │   │   │   DVWA      │     │   Wazuh    │  │   │
          │   │   │ (Docker)    │────▶│  (SIEM)    │  │   │
          │   │   │  target     │ logs│ manager +  │  │   │
          │   │   │  web app    │     │ indexer +  │  │   │
          │   │   └────────────┘     │ dashboard  │  │   │
          │   │         ▲            └────────────┘  │   │
          │   │         │ attack traffic             │   │
          │   │   ┌────────────┐                     │   │
          │   │   │  Attack     │                     │   │
          │   │   │  tooling    │                     │   │
          │   │   └────────────┘                     │   │
          │   └──────────────────────────────────────┘   │
          └─────────────────────────────────────────────┘
```

**Components:**
- **Kali Linux VM** — isolated with two network adapters (NAT for updates, host-only for the lab network) so attack traffic stays contained.
- **DVWA (Damn Vulnerable Web Application)** — runs as a Docker container; the monitored target.
- **Wazuh (all-in-one)** — the SIEM: indexer + manager + dashboard. Collects and analyzes logs, applies detection rules, and surfaces alerts.

---

## Setup

### 1. The target (DVWA)

DVWA runs as a Docker container, with its Apache logs mounted out to a fixed host path so the SIEM can read them reliably across restarts:

```bash
docker run -d -p 80:80 -v /var/log/dvwa:/var/log/apache2 --name dvwa vulnerables/web-dvwa
```

### 2. The SIEM (Wazuh)

Wazuh was installed using the official all-in-one installer. After install, I pointed the manager at DVWA's access log by adding a log source to the Wazuh configuration (`ossec.conf`):

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/dvwa/access.log</location>
</localfile>
```

A manager restart activated the new log source, completing the pipeline: **web request → Apache log → Wazuh decoder → detection rule → alert.**

---

## Attack Simulation

To validate detection coverage, I generated attack traffic against DVWA using a mix of **manual payloads** and an **automated web vulnerability scan** (nikto). Examples of manual probes:

```bash
# Directory traversal attempt
curl -s "http://localhost/?page=../../../../etc/passwd"

# Cross-site scripting (XSS) probe
curl -s "http://localhost/?search=<script>alert(1)</script>"

# Scanner-style requests for non-existent paths
curl -s "http://localhost/admin.php"
curl -s "http://localhost/phpmyadmin/"
```

The automated scan generated **~7,700 events** in a single short burst — immediately visible on the dashboard as a sharp spike. This is the classic signature of automated scanning: a massive volume of alerts from a single source in a very short window.

> **Screenshot placeholder:** `![Alert spike after scan](screenshots/dashboard-spike.png)`
> <img width="1568" height="718" alt="image" src="https://github.com/user-attachments/assets/0ae958c0-1465-4433-949a-97abdf1b20c5" />


> *The dashboard jumping from ~15 alerts to thousands after the scan.*

---

## Detection & Investigation

This is the heart of the project. A flood of 7,700 alerts is not 7,700 incidents — the analyst's job is to pull the signal out of the noise.

### Step 1 — Triage: filter to what matters

Using the Threat Hunting view, I filtered to high-severity alerts only:

```
rule.level >= 12
```

Of ~7,700 total events, this surfaced **5 critical (level 15) alerts** — everything else was low-severity scanner noise. First question answered: *is there anything that needs a human? Yes — these five.*

> **Screenshot placeholder:** `![Critical alerts filtered](screenshots/critical-alerts.png)`
> <img width="1913" height="870" alt="image" src="https://github.com/user-attachments/assets/98bd9a4d-cd66-422d-a914-12ba1c1fd8ef" />

### Step 2 — Identify the alert

All five critical alerts were:

| Field | Value |
|---|---|
| Rule description | Shellshock attack detected |
| Rule ID | 31168 |
| Rule level | 15 (critical) |
| CVE | CVE-2014-6271 (and CVE-2014-6278) |
| Source IP | 172.17.0.1 (the scanner) |
| Timestamp | All within ~1 second |

**Shellshock (CVE-2014-6271)** is a 2014 Bash vulnerability allowing remote command execution via crafted HTTP headers. Wazuh rates any attempt as level 15 because successful exploitation means full command execution on the server.

> **Screenshot placeholder:** `![Shellshock alert detail](screenshots/shellshock-detail.png)`

### Step 3 — Examine the payload

The raw log showed the Shellshock signature in the request:

```
() { :; }; echo ...CVE-2014-6271: true;echo;echo;
() { _; } >_[$($())] { echo ...CVE-2014-6278: true; echo;echo; }
```

The `() { :; };` pattern is the malformed Bash function definition that, on a vulnerable server, causes the following command to execute. The scanner appended a test (`echo ...: true`) to check whether the target would respond as vulnerable.

### Step 4 — The key judgment: attempt vs. success

A level-15 alert sounds like an emergency. But investigation showed this was an **unsuccessful probe**, not a compromise:

1. **Response code was HTTP 302** (a normal redirect), not command output. A successful Shellshock exploit would not return a clean redirect.
2. **The target's Bash was patched** — Shellshock was fixed in 2014; the server was not vulnerable.
3. **Context:** 5 identical hits in ~1 second from a single IP, as part of a ~7,700-event automated scan. This is a scanner ticking a checkbox, not a targeted attacker who found a foothold.

### Step 5 — Verdict (triage note)

> Rule 31168 (level 15) "Shellshock attack detected" — 5× from 172.17.0.1 at 14:20:52, part of an automated web vulnerability scan. Payloads matched CVE-2014-6271 / CVE-2014-6278 test strings. Server returned HTTP 302; target not vulnerable (patched Bash). **Verdict: attempted exploitation, unsuccessful.** Classification: reconnaissance / scanning activity, single source. Priority: informational — note the scanning source; no evidence of compromise.

---

## Key Takeaways

- **A SIEM is a workflow, not a magic box.** Logs come in, rules match, alerts surface, and a human investigates. Building Wazuh end to end made that loop concrete.
- **Severity ≠ impact.** A "critical" alert can turn out to be a failed scanner probe. The analyst's value is determining which is which, rather than escalating everything.
- **Volume is a signal.** Thousands of alerts from one source in seconds reads as *one* scanning event, not thousands of incidents — recognizing that pattern is core triage.
- **Context decides the verdict.** Response codes, target patch level, and source behavior together turned a scary-looking level-15 alert into a correctly-classified, low-priority event.
- **MITRE ATT&CK mapping** connects raw alerts to recognized adversary techniques (e.g. Exploit Public-Facing Application), which is how detections become a shared language across a SOC.

---

## Tools Used

- **Wazuh** — SIEM / XDR (detection, alerting, investigation)
- **DVWA** — intentionally vulnerable web app (target)
- **Docker** — containerized target deployment
- **Kali Linux** — lab platform
- **nikto** — web vulnerability scanner (attack simulation)

---

*This lab was built in an isolated environment against targets I own, for defensive learning and detection practice only.*
