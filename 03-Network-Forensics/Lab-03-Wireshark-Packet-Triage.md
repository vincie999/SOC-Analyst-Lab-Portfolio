# Lab 03: Network Packet Triage & Deep-Packet Forensics (Wireshark)

## 1. Executive Summary & Objective
Following initial SIEM discovery of unauthorized API transfers (`Lab 02`), a deep-dive network investigation was initiated using Wireshark to inspect packet payloads, verify destination communication channels, and isolate potential Command and Control (C2) or data exfiltration traffic linked to IP `203.0.113.42`.

---

## 2. Investigation Methodology & Filters

When moving from SIEM alerts to packet analysis, analysts utilize specific Wireshark display filters to isolate relevant communication streams:

* **Isolate Host Traffic:** 
  ```wireshark
  ip.addr == 203.0.113.42
