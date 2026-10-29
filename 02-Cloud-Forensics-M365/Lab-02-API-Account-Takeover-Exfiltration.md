# Lab 02: API Account Takeover (ATO) & Unauthorized Crypto Exfiltration

## 1. Executive Summary & Attack Story
During a threat hunting exercise on API transactional logs (`bank_logs.json.json`), an anomaly was identified involving rapid, high-value transfers initiated by administrative credentials. Raw log analysis revealed a classic **Account Takeover (ATO)** sequence: initial brute-force login attempts, a successful authentication event, and immediate fund exfiltration to an external destination within 4 minutes.

---

## 2. Attack Chain Timeline

| Timestamp | Event Action | Status | User | Source IP | Details / Impact |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **10:15:00** | `login` | Failed | `admin_service` | `203.0.113.42` | Brute force / Credential stuffing attempt |
| **10:15:05** | `login` | Failed | `admin_service` | `203.0.113.42` | Secondary login failure |
| **10:15:10** | `login` | **Success** | `admin_service` | `203.0.113.42` | **Account Compromise** |
| **10:18:22** | `transfer` | Executed | `admin_service` | `203.0.113.42` | Test transfer: 50,000 units $\rightarrow$ `CRYPTO-ROUTING-99` |
| **10:19:01** | `transfer` | Executed | `admin_service` | `203.0.113.42` | Primary drain: 100,000 units $\rightarrow$ `CRYPTO-ROUTING-99` |

---

## 3. Threat Hunting & Investigation Query (SPL)

To reconstruct the timeline and summarize the impact per user and source IP:

```spl
index=main sourcetype=_json
| table timestamp, user, src_ip, action, status, amount, destination_account
| sort timestamp
